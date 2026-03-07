#!/usr/bin/env python3
"""
DVWA Browser Agent — LLM-driven Playwright browser that navigates DVWA.

Uses Grok (xAI) via the native xai-sdk for fast (~1s) agentic decisions.
Each action is independently steered by the LLM based on the current page state.
Generates real browser traffic through the spectral firewall proxy.
"""

import argparse
import asyncio
import functools
import os
import random
import signal
import sys
import time
from dataclasses import dataclass

from xai_sdk import Client as XaiClient
from xai_sdk.chat import user as xai_user
from playwright.async_api import async_playwright, Page


@dataclass
class AgentConfig:
    proxy_url: str
    dvwa_url: str
    session_cookie: str
    security_level: str = "low"
    pace_min: float = 0.5
    pace_max: float = 2.0
    xai_api_key: str = ""
    xai_model: str = "grok-4-fast"
    headless: bool = True
    browser_type: str = "chromium"


_shutdown = asyncio.Event()


def _handle_signal(*_):
    _shutdown.set()


def _llm_sample(client: XaiClient, model: str, prompt: str) -> str:
    """Synchronous xai-sdk call — run via asyncio.to_thread for non-blocking."""
    chat = client.chat.create(model=model)
    chat.append(xai_user(prompt))
    resp = chat.sample()
    return resp.content.strip()


class DVWABrowserAgent:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.llm = XaiClient(api_key=config.xai_api_key)
        self.action_count = 0
        self.start_time = 0.0
        self.history: list[str] = []
        self.forms_submitted: set[str] = set()

    async def _ask_llm(self, prompt: str) -> str:
        return await asyncio.to_thread(
            _llm_sample, self.llm, self.config.xai_model, prompt
        )

    async def run(self):
        self.start_time = time.time()
        print(f"[agent] Starting {self.config.browser_type} browser")
        print(f"[agent] Proxy: {self.config.proxy_url}")
        print(f"[agent] Model: {self.config.xai_model}")

        async with async_playwright() as pw:
            launcher = getattr(pw, self.config.browser_type)
            browser = await launcher.launch(
                headless=self.config.headless,
                args=["--ignore-certificate-errors"] if self.config.browser_type == "chromium" else [],
            )

            context = await browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1920, "height": 1080},
                extra_http_headers={"X-Traffic-Source": "browser-agent"},
            )

            is_https = self.config.proxy_url.startswith("https")
            if self.config.session_cookie:
                proxy_domain = self.config.proxy_url.split("://")[1].split(":")[0]
                await context.add_cookies([{
                    "name": "PHPSESSID",
                    "value": self.config.session_cookie,
                    "domain": proxy_domain,
                    "path": "/",
                    "secure": is_https,
                    "sameSite": "Lax",
                }, {
                    "name": "security",
                    "value": self.config.security_level,
                    "domain": proxy_domain,
                    "path": "/",
                    "secure": is_https,
                    "sameSite": "Lax",
                }])

            page = await context.new_page()

            try:
                if not self.config.session_cookie:
                    await self._auto_login(page, context)

                print(f"[agent] Loading DVWA index...")
                for attempt in range(5):
                    try:
                        await page.goto(
                            f"{self.config.proxy_url}/index.php",
                            wait_until="networkidle",
                            timeout=15000,
                        )
                        break
                    except Exception as e:
                        if attempt == 4:
                            raise
                        wait = 2 ** attempt
                        print(f"[agent] Initial load failed ({e}), retry in {wait}s...")
                        await asyncio.sleep(wait)

                print(f"[agent] Page loaded: {await page.title()}")

                consecutive_errors = 0
                while not _shutdown.is_set():
                    self.action_count += 1

                    try:
                        t0 = time.time()
                        page_info = await self._get_page_info(page)
                        page_key = page_info["url"].split("?")[0].split("/")[-1]
                        if page_key in self.forms_submitted:
                            page_info["has_form"] = False
                            page_info["form_inputs"] = []
                        t1 = time.time()
                        action = await self._decide_action(page_info)
                        t2 = time.time()
                        await self._execute_action(page, action, page_info)
                        t3 = time.time()
                        if action["action"] == "form":
                            self.forms_submitted.add(page_key)
                        print(f"[timing] scrape={t1-t0:.2f}s llm={t2-t1:.2f}s exec={t3-t2:.2f}s")
                        consecutive_errors = 0
                    except Exception as e:
                        consecutive_errors += 1
                        print(f"[agent] Action error ({consecutive_errors}): {e}")
                        if consecutive_errors >= 5:
                            print(f"[agent] Too many consecutive errors, reloading index...")
                            try:
                                await page.goto(
                                    f"{self.config.proxy_url}/index.php",
                                    wait_until="networkidle",
                                    timeout=15000,
                                )
                                consecutive_errors = 0
                            except Exception as e2:
                                print(f"[agent] Reload also failed: {e2}")
                                if consecutive_errors >= 10:
                                    print(f"[agent] Giving up after 10 consecutive errors")
                                    break
                        await asyncio.sleep(2)
                        continue

                    delay = random.uniform(self.config.pace_min, self.config.pace_max)
                    try:
                        await asyncio.wait_for(_shutdown.wait(), timeout=delay)
                        break
                    except asyncio.TimeoutError:
                        pass

            except Exception as e:
                print(f"[agent] Fatal error: {e}")
            finally:
                elapsed = time.time() - self.start_time
                print(f"[agent] Done: {elapsed:.0f}s, {self.action_count} actions")
                await context.close()
                await browser.close()

    async def _auto_login(self, page: Page, context):
        print("[agent] Auto-login: navigating to login page...")
        await page.goto(
            f"{self.config.proxy_url}/login.php",
            wait_until="networkidle",
            timeout=15000,
        )
        await page.fill('input[name="username"]', "admin")
        await page.fill('input[name="password"]', "password")
        await page.click('input[type="submit"]')
        await page.wait_for_load_state("networkidle", timeout=10000)

        proxy_domain = self.config.proxy_url.split("://")[1].split(":")[0]
        is_https = self.config.proxy_url.startswith("https")
        await context.add_cookies([{
            "name": "security",
            "value": self.config.security_level,
            "domain": proxy_domain,
            "path": "/",
            "secure": is_https,
            "sameSite": "Lax",
        }])
        print(f"[agent] Auto-login: success, title={await page.title()}")

    async def _get_page_info(self, page: Page) -> dict:
        title = await page.title()
        url = page.url

        content = await page.evaluate("""
            () => {
                const main = document.querySelector('.body_padded, #main_body, .vulnerable_code_area, main');
                if (main) return main.innerText.substring(0, 800);
                return document.body.innerText.substring(0, 800);
            }
        """)

        nav_links = await page.evaluate("""
            () => {
                return Array.from(document.querySelectorAll('.menuBlocks a, #main_menu a, ul.menuBlocks a'))
                    .map((a, idx) => ({
                        number: idx + 1,
                        text: a.innerText.trim(),
                        href: a.getAttribute('href')
                    }))
                    .filter(l => l.text && l.href)
                    .slice(0, 20);
            }
        """)

        page_links = await page.evaluate("""
            () => {
                return Array.from(document.querySelectorAll('.body_padded a, #main_body a'))
                    .map((a, idx) => ({
                        number: idx + 1,
                        text: a.innerText.trim().substring(0, 80),
                        href: a.getAttribute('href')
                    }))
                    .filter(l => l.text && l.href && !l.href.startsWith('#') && !l.href.startsWith('javascript'))
                    .slice(0, 10);
            }
        """)

        has_form = await page.query_selector("form") is not None
        form_inputs = []
        if has_form:
            form_inputs = await page.evaluate("""
                () => {
                    return Array.from(document.querySelectorAll('form input, form textarea, form select'))
                        .map(el => ({
                            tag: el.tagName.toLowerCase(),
                            type: el.type || '',
                            name: el.name || '',
                            placeholder: el.placeholder || ''
                        }))
                        .filter(el => el.type !== 'hidden' && el.type !== 'submit' && el.name)
                        .slice(0, 8);
                }
            """)

        return {
            "title": title,
            "url": url,
            "content": content[:800],
            "nav_links": nav_links,
            "page_links": page_links,
            "has_form": has_form,
            "form_inputs": form_inputs,
        }

    async def _decide_action(self, page_info: dict) -> dict:
        nav_text = "\n".join(
            f"  {l['number']}. {l['text']}" for l in page_info["nav_links"]
        ) or "  (none)"

        link_text = "\n".join(
            f"  {l['number']}. {l['text']}" for l in page_info["page_links"]
        ) or "  (none)"

        form_text = ""
        if page_info["form_inputs"]:
            form_text = "\nFORM FIELDS: " + ", ".join(
                f"{f['name']} ({f['type']})" for f in page_info["form_inputs"]
                if f["name"] != "security"
            )

        history_text = ""
        if self.history:
            recent = self.history[-8:]
            history_text = "\nYOUR HISTORY (oldest→newest): " + " → ".join(recent)

        prompt = f"""You are exploring DVWA. Browse only, never exploit.

PAGE: {page_info['title']}

CONTENT:
{page_info['content'][:400]}

NAV MENU:
{nav_text}

PAGE LINKS:
{link_text}
{form_text}{history_text}

Reply exactly 3 lines:
ACTION: NAV|LINK|FORM|BACK
TARGET: number for NAV/LINK, or field=value for FORM
REASON: why

RULES: You MUST use NAV to visit a different section you haven't been to recently. Only use FORM if fields are listed above AND you haven't tried this page's form yet. Never change security level. Prioritize unvisited sections."""

        try:
            text = await self._ask_llm(prompt)
        except Exception as e:
            print(f"[agent] LLM error: {e}")
            return {"action": "nav", "target": random.randint(1, max(1, len(page_info["nav_links"])))}

        action = "nav"
        target = ""
        reason = ""
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("ACTION:"):
                raw = line.split(":", 1)[1].strip().upper()
                if "NAV" in raw:
                    action = "nav"
                elif "LINK" in raw:
                    action = "link"
                elif "FORM" in raw:
                    action = "form"
                elif "BACK" in raw:
                    action = "back"
            elif line.startswith("TARGET:"):
                target = line.split(":", 1)[1].strip()
            elif line.startswith("REASON:"):
                reason = line.split(":", 1)[1].strip()

        page_short = page_info['title'].split('::')[0].strip()
        summary = f"{action.upper()} {target} [{page_short}]"
        print(f"[agent] #{self.action_count} {summary} — {reason}")
        self.history.append(f"{action.upper()} {page_short}")

        target_num = 0
        try:
            target_num = int("".join(c for c in target if c.isdigit()) or "0")
        except ValueError:
            pass

        return {"action": action, "target": target_num, "target_raw": target}

    async def _execute_action(self, page: Page, action: dict, page_info: dict):
        act = action["action"]

        if act == "nav":
            links = page_info["nav_links"]
            idx = action["target"] - 1
            if links:
                if not (0 <= idx < len(links)):
                    idx = random.randint(0, len(links) - 1)
                href = links[idx]["href"]
                url = href if href.startswith("http") else f"{self.config.proxy_url}/{href.lstrip('/')}"
                try:
                    await page.goto(url, wait_until="networkidle", timeout=10000)
                except Exception as e:
                    print(f"[agent] Nav failed: {e}")

        elif act == "link":
            links = page_info["page_links"]
            idx = action["target"] - 1
            if links:
                if not (0 <= idx < len(links)):
                    idx = random.randint(0, len(links) - 1)
                href = links[idx]["href"]
                url = href if href.startswith("http") else f"{self.config.proxy_url}/{href.lstrip('/')}"
                try:
                    await page.goto(url, wait_until="networkidle", timeout=10000)
                except Exception as e:
                    print(f"[agent] Link failed: {e}")

        elif act == "form" and page_info["has_form"]:
            try:
                benign_values = ["hello", "test", "student", "Alice", "42",
                                 "example.com", "bob", "welcome", "127.0.0.1"]
                for inp in page_info["form_inputs"]:
                    if inp["name"] == "security":
                        continue
                    selector = f'[name="{inp["name"]}"]'
                    el = await page.query_selector(selector)
                    if not el:
                        continue
                    if inp["tag"] == "select":
                        options = await el.evaluate(
                            "el => Array.from(el.options).map(o => o.value).filter(v => v)"
                        )
                        if options:
                            await el.select_option(random.choice(options))
                    else:
                        await el.fill(random.choice(benign_values))

                submit = await page.query_selector(
                    'form input[type="submit"], form button[type="submit"], form button:not([type])'
                )
                if submit:
                    await submit.click()
                    await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception as e:
                print(f"[agent] Form error: {e}")

        elif act == "back":
            try:
                await page.goto(
                    f"{self.config.proxy_url}/index.php",
                    wait_until="networkidle",
                    timeout=10000,
                )
            except Exception as e:
                print(f"[agent] Back failed: {e}")


async def main():
    parser = argparse.ArgumentParser(description="DVWA LLM Browser Agent")
    parser.add_argument("--proxy-url", default="https://127.0.0.1:8443",
                        help="Spectral firewall proxy URL")
    parser.add_argument("--dvwa-url", default="http://127.0.0.1:8888",
                        help="Direct DVWA URL (for reference)")
    parser.add_argument("--session-cookie", default="",
                        help="PHPSESSID cookie value (auto-login if omitted)")
    parser.add_argument("--security-level", default="low",
                        help="DVWA security level cookie")
    parser.add_argument("--pace-min", type=float, default=0.5,
                        help="Min seconds between actions")
    parser.add_argument("--pace-max", type=float, default=2.0,
                        help="Max seconds between actions")
    parser.add_argument("--model", default="grok-4-fast",
                        help="xAI model name")
    parser.add_argument("--browser", default="chromium",
                        choices=["chromium", "webkit", "firefox"],
                        help="Browser engine")
    parser.add_argument("--no-headless", action="store_true",
                        help="Show the browser window")
    parser.add_argument("--duration", type=int, default=0,
                        help="Run for N seconds then stop (0=until killed)")
    args = parser.parse_args()

    api_key = os.environ.get("XAI_API_KEY", "")
    if not api_key:
        print("ERROR: XAI_API_KEY environment variable not set")
        sys.exit(1)

    config = AgentConfig(
        proxy_url=args.proxy_url.rstrip("/"),
        dvwa_url=args.dvwa_url.rstrip("/"),
        session_cookie=args.session_cookie,
        security_level=args.security_level,
        pace_min=args.pace_min,
        pace_max=args.pace_max,
        xai_api_key=api_key,
        xai_model=args.model,
        headless=not args.no_headless,
        browser_type=args.browser,
    )

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _handle_signal)

    if args.duration > 0:
        asyncio.get_event_loop().call_later(args.duration, _handle_signal)

    agent = DVWABrowserAgent(config)
    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())
