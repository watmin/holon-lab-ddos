#!/usr/bin/env python3
"""
xAI API latency diagnostic — compares OpenAI SDK, native xai-sdk, and raw httpx.
Tests non-streaming and streaming for each approach.
"""
import asyncio
import json
import os
import sys
import time

import httpx
from openai import AsyncOpenAI
from xai_sdk import Client as XaiClient, AsyncClient as XaiAsyncClient
from xai_sdk.chat import user

MODEL = sys.argv[1] if len(sys.argv) > 1 else "grok-4-1-fast-reasoning"
PROMPT = "Say hi in 3 words"
ROUNDS = 5
API_KEY = os.environ.get("XAI_API_KEY", "")

if not API_KEY:
    print("XAI_API_KEY not set")
    sys.exit(1)


def stats(times: list[float]) -> str:
    mn = min(times)
    mx = max(times)
    avg = sum(times) / len(times)
    return f"min={mn:.2f}s avg={avg:.2f}s max={mx:.2f}s"


async def test_openai_sdk():
    """OpenAI-compatible SDK via chat.completions.create"""
    print(f"\n{'='*50}")
    print(f"1. OpenAI SDK (chat.completions.create)")
    print(f"{'='*50}")

    client = AsyncOpenAI(api_key=API_KEY, base_url="https://api.x.ai/v1")

    times = []
    for i in range(ROUNDS):
        t0 = time.time()
        resp = await client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": PROMPT}],
            max_tokens=15,
        )
        dt = time.time() - t0
        times.append(dt)
        text = resp.choices[0].message.content.strip()
        tok_in = resp.usage.prompt_tokens
        tok_out = resp.usage.completion_tokens
        print(f"  [{i+1}] {dt:.2f}s  in={tok_in} out={tok_out}  → {text}")

    print(f"  ** {stats(times)}")

    # Streaming
    print(f"  --- streaming ---")
    stimes = []
    for i in range(ROUNDS):
        t0 = time.time()
        ttft = None
        chunks = []
        stream = await client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": PROMPT}],
            max_tokens=15,
            stream=True,
        )
        async for chunk in stream:
            if ttft is None:
                ttft = time.time() - t0
            if chunk.choices and chunk.choices[0].delta.content:
                chunks.append(chunk.choices[0].delta.content)
        dt = time.time() - t0
        stimes.append(dt)
        text = "".join(chunks).strip()
        print(f"  [{i+1}] ttft={ttft:.2f}s total={dt:.2f}s  → {text}")
    print(f"  ** {stats(stimes)}")

    await client.close()


def test_xai_sdk_sync():
    """Native xai-sdk (sync client)"""
    print(f"\n{'='*50}")
    print(f"2. xai-sdk (sync Client)")
    print(f"{'='*50}")

    client = XaiClient(api_key=API_KEY)

    times = []
    for i in range(ROUNDS):
        chat = client.chat.create(model=MODEL)
        chat.append(user(PROMPT))
        t0 = time.time()
        resp = chat.sample()
        dt = time.time() - t0
        times.append(dt)
        print(f"  [{i+1}] {dt:.2f}s  → {resp.content.strip()}")

    print(f"  ** {stats(times)}")

    # Streaming
    print(f"  --- streaming ---")
    stimes = []
    for i in range(ROUNDS):
        chat = client.chat.create(model=MODEL)
        chat.append(user(PROMPT))
        t0 = time.time()
        ttft = None
        chunks = []
        for resp, chunk in chat.stream():
            if ttft is None:
                ttft = time.time() - t0
            chunks.append(chunk.content)
        dt = time.time() - t0
        stimes.append(dt)
        text = "".join(chunks).strip()
        print(f"  [{i+1}] ttft={ttft:.2f}s total={dt:.2f}s  → {text}")
    print(f"  ** {stats(stimes)}")


async def test_raw_httpx():
    """Raw httpx POST to /v1/chat/completions"""
    print(f"\n{'='*50}")
    print(f"3. Raw httpx (direct HTTP POST)")
    print(f"{'='*50}")

    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        }
        body = {
            "model": MODEL,
            "messages": [{"role": "user", "content": PROMPT}],
            "max_tokens": 15,
        }

        times = []
        for i in range(ROUNDS):
            t0 = time.time()
            r = await client.post(
                "https://api.x.ai/v1/chat/completions",
                headers=headers,
                json=body,
            )
            dt = time.time() - t0
            times.append(dt)
            data = r.json()
            text = data["choices"][0]["message"]["content"].strip()
            tok_in = data["usage"]["prompt_tokens"]
            tok_out = data["usage"]["completion_tokens"]
            print(f"  [{i+1}] {dt:.2f}s  http={r.status_code}  in={tok_in} out={tok_out}  → {text}")

        print(f"  ** {stats(times)}")

    # Streaming via httpx
    print(f"  --- streaming ---")
    async with httpx.AsyncClient(timeout=30.0) as client:
        headers = {
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        }
        body_s = {
            "model": MODEL,
            "messages": [{"role": "user", "content": PROMPT}],
            "max_tokens": 15,
            "stream": True,
        }
        stimes = []
        for i in range(ROUNDS):
            t0 = time.time()
            ttft = None
            chunks = []
            async with client.stream(
                "POST",
                "https://api.x.ai/v1/chat/completions",
                headers=headers,
                json=body_s,
            ) as resp:
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    payload = line[6:]
                    if payload == "[DONE]":
                        break
                    obj = json.loads(payload)
                    if ttft is None:
                        ttft = time.time() - t0
                    delta = obj.get("choices", [{}])[0].get("delta", {})
                    if "content" in delta and delta["content"]:
                        chunks.append(delta["content"])
            dt = time.time() - t0
            stimes.append(dt)
            text = "".join(chunks).strip()
            ttft_s = f"{ttft:.2f}s" if ttft else "?"
            print(f"  [{i+1}] ttft={ttft_s} total={dt:.2f}s  → {text}")
        print(f"  ** {stats(stimes)}")


async def main():
    print(f"xAI API Latency Diagnostic")
    print(f"Model: {MODEL}")
    print(f"Prompt: \"{PROMPT}\"")
    print(f"Rounds: {ROUNDS}")

    await test_openai_sdk()
    test_xai_sdk_sync()
    await test_raw_httpx()

    print(f"\n{'='*50}")
    print(f"Done.")


asyncio.run(main())
