#!/usr/bin/env python3
"""
Launch multiple DVWA browser agents with realistic browser distribution,
each routed through a different source IP via the TCP forwarders.

Usage:
    python multi_agent.py --agents 10 --duration 120

Browser distribution mirrors real-world traffic:
  80% chromium, 15% webkit (Safari), 5% firefox

Each agent gets a unique forwarder port (50001, 50002, ...) so the
spectral proxy sees traffic from different source IPs.
"""

import argparse
import os
import random
import signal
import subprocess
import sys
import time

BROWSER_WEIGHTS = [
    ("chromium", 0.80),
    ("webkit",   0.15),
    ("firefox",  0.05),
]


def assign_browsers(count: int) -> list[str]:
    """Assign browser types respecting the weight distribution."""
    result = []
    remaining = count
    for browser, weight in BROWSER_WEIGHTS[:-1]:
        n = round(count * weight)
        n = min(n, remaining)
        result.extend([browser] * n)
        remaining -= n
    result.extend([BROWSER_WEIGHTS[-1][0]] * remaining)

    # Ensure at least 1 of each minority browser when count >= 3
    browsers_present = set(result)
    if count >= 3:
        for browser, _ in BROWSER_WEIGHTS:
            if browser not in browsers_present:
                # Swap one chromium for the missing browser
                for i in range(len(result) - 1, -1, -1):
                    if result[i] == "chromium":
                        result[i] = browser
                        break

    random.shuffle(result)
    return result


def main():
    parser = argparse.ArgumentParser(description="Multi-agent DVWA browser launcher")
    parser.add_argument("--agents", type=int, default=10,
                        help="Number of concurrent browser agents")
    parser.add_argument("--duration", type=int, default=120,
                        help="Run duration in seconds")
    parser.add_argument("--session-cookie", default="",
                        help="PHPSESSID (auto-login if omitted)")
    parser.add_argument("--base-port", type=int, default=50001,
                        help="First forwarder port")
    parser.add_argument("--direct-url", default="",
                        help="Skip forwarders, all agents use this URL directly")
    parser.add_argument("--model", default="grok-4-fast",
                        help="xAI model")
    parser.add_argument("--pace-min", type=float, default=0.5)
    parser.add_argument("--pace-max", type=float, default=2.0)
    parser.add_argument("--stagger", type=float, default=2.0,
                        help="Seconds between agent launches")
    args = parser.parse_args()

    if not os.environ.get("XAI_API_KEY"):
        print("ERROR: XAI_API_KEY not set")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    agent_script = os.path.join(script_dir, "dvwa_browser_agent.py")
    venv_python = os.path.join(script_dir, ".venv", "bin", "python")

    if not os.path.exists(venv_python):
        venv_python = sys.executable

    browsers = assign_browsers(args.agents)

    browser_counts = {}
    for b in browsers:
        browser_counts[b] = browser_counts.get(b, 0) + 1

    procs: list[subprocess.Popen] = []

    def cleanup(*_):
        print(f"\n[launcher] Stopping {len(procs)} agents...")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    print(f"[launcher] Starting {args.agents} browser agents")
    print(f"[launcher] Duration: {args.duration}s")
    print(f"[launcher] Browser mix: {browser_counts}")
    if args.direct_url:
        print(f"[launcher] Direct mode: all agents → {args.direct_url}")
    else:
        print(f"[launcher] Source IPs: 10.99.0.1-10.99.0.{args.agents}")
        print(f"[launcher] Forwarder ports: {args.base_port}-{args.base_port + args.agents - 1}")
    print()

    log_dir = os.path.join(script_dir, "agent_logs")
    os.makedirs(log_dir, exist_ok=True)

    for i in range(args.agents):
        port = args.base_port + i
        proxy_url = args.direct_url if args.direct_url else f"https://127.0.0.1:{port}"
        browser = browsers[i]
        log_file = os.path.join(log_dir, f"agent_{i+1}_{browser}.log")

        cmd = [
            venv_python, agent_script,
            "--proxy-url", proxy_url,
            "--dvwa-url", "http://127.0.0.1:8888",
            "--duration", str(args.duration),
            "--model", args.model,
            "--browser", browser,
            "--pace-min", str(args.pace_min),
            "--pace-max", str(args.pace_max),
        ]
        if args.session_cookie:
            cmd.extend(["--session-cookie", args.session_cookie])

        with open(log_file, "w") as lf:
            p = subprocess.Popen(
                cmd,
                stdout=lf,
                stderr=subprocess.STDOUT,
                env=os.environ.copy(),
            )
            procs.append(p)
            label = args.direct_url or f"10.99.0.{i+1} (port {port})"
            print(f"  Agent {i+1}: pid={p.pid} {browser:10s} → {label}")

        time.sleep(args.stagger)

    print()
    print(f"[launcher] All {args.agents} agents running. Waiting {args.duration}s...")

    start = time.time()
    while time.time() - start < args.duration + 10:
        all_done = all(p.poll() is not None for p in procs)
        if all_done:
            break
        time.sleep(10)
        alive = sum(1 for p in procs if p.poll() is None)
        elapsed = int(time.time() - start)
        print(f"  [{elapsed}s] {alive}/{args.agents} agents alive")

    print()
    print("[launcher] Run complete. Agent summaries:")
    total_actions = 0
    for i, p in enumerate(procs):
        if p.poll() is None:
            p.terminate()
            p.wait(timeout=5)
        log_file = os.path.join(log_dir, f"agent_{i+1}_{browsers[i]}.log")
        try:
            with open(log_file) as f:
                lines = f.readlines()
            done_line = [l for l in lines if "[agent] Done:" in l]
            if done_line:
                summary = done_line[-1].strip()
                print(f"  Agent {i+1} ({browsers[i]:10s} → 10.99.0.{i+1}): {summary}")
                import re
                m = re.search(r"(\d+) actions", summary)
                if m:
                    total_actions += int(m.group(1))
            else:
                err_lines = [l.strip() for l in lines if "Error" in l or "error" in l]
                if err_lines:
                    print(f"  Agent {i+1} ({browsers[i]:10s}): ERROR — {err_lines[0]}")
                else:
                    print(f"  Agent {i+1} ({browsers[i]:10s}): (no completion line)")
        except Exception:
            print(f"  Agent {i+1} ({browsers[i]:10s}): (log not readable)")

    print(f"\n[launcher] Total: {total_actions} actions across {args.agents} agents")


if __name__ == "__main__":
    main()
