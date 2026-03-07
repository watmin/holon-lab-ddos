#!/usr/bin/env python3
"""
TCP forwarders that bind outgoing connections to specific source IPs.

Each forwarder listens on 127.0.0.1:5000N and forwards raw TCP to the
spectral proxy at 10.99.0.100:8443, binding the outgoing socket to
10.99.0.N. TLS passes through transparently (end-to-end browser↔proxy).

Usage:
    sudo ./setup-local-network.sh 10    # create dummy0 with 10 IPs
    python source_forwarder.py           # start 10 forwarders

Then point browser agents at https://127.0.0.1:50001 through :50010.
The spectral proxy sees source IPs 10.99.0.1 through 10.99.0.10.
"""

import argparse
import asyncio
import signal
import socket
import sys


DEFAULT_PROXY_TARGET = "10.99.0.100"
DEFAULT_PROXY_PORT = 8443
LISTEN_HOST = "127.0.0.1"
DEFAULT_BASE_PORT = 50001
SOURCE_SUBNET = "10.99.0"


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def handle_connection(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    source_ip: str,
    forwarder_id: int,
    proxy_target: str,
    proxy_port: int,
):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)

    try:
        sock.bind((source_ip, 0))
    except OSError as e:
        print(f"[fwd-{forwarder_id}] bind to {source_ip} failed: {e}")
        client_writer.close()
        sock.close()
        return

    loop = asyncio.get_event_loop()
    try:
        await loop.sock_connect(sock, (proxy_target, proxy_port))
    except OSError as e:
        print(f"[fwd-{forwarder_id}] connect to {proxy_target}:{proxy_port} failed: {e}")
        client_writer.close()
        sock.close()
        return

    upstream_reader, upstream_writer = await asyncio.open_connection(sock=sock)

    await asyncio.gather(
        pipe(client_reader, upstream_writer),
        pipe(upstream_reader, client_writer),
    )


async def run_forwarder(forwarder_id: int, source_ip: str, listen_port: int,
                        proxy_target: str, proxy_port: int):
    try:
        server = await asyncio.start_server(
            lambda r, w: handle_connection(r, w, source_ip, forwarder_id, proxy_target, proxy_port),
            LISTEN_HOST,
            listen_port,
        )
    except OSError as e:
        print(f"  [fwd-{forwarder_id}] FAILED to bind {LISTEN_HOST}:{listen_port}: {e}")
        return False
    print(f"  [fwd-{forwarder_id}] {LISTEN_HOST}:{listen_port} → {proxy_target}:{proxy_port} (source {source_ip})")
    async with server:
        await server.serve_forever()
    return True


async def main():
    parser = argparse.ArgumentParser(description="Source-binding TCP forwarders")
    parser.add_argument("--count", type=int, default=10,
                        help="Number of forwarders (default: 10)")
    parser.add_argument("--proxy-target", default=DEFAULT_PROXY_TARGET,
                        help=f"Proxy address (default: {DEFAULT_PROXY_TARGET})")
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT,
                        help=f"Proxy port (default: {DEFAULT_PROXY_PORT})")
    parser.add_argument("--base-port", type=int, default=DEFAULT_BASE_PORT,
                        help=f"First listen port (default: {DEFAULT_BASE_PORT})")
    args = parser.parse_args()

    proxy_target = args.proxy_target
    proxy_port = args.proxy_port

    print(f"Starting {args.count} TCP forwarders")
    print(f"  Target: {proxy_target}:{proxy_port}")
    print(f"  Ports:  {LISTEN_HOST}:{args.base_port}-{args.base_port + args.count - 1}")
    print()

    tasks = []
    for i in range(args.count):
        source_ip = f"{SOURCE_SUBNET}.{i + 1}"
        listen_port = args.base_port + i
        tasks.append(run_forwarder(i + 1, source_ip, listen_port, proxy_target, proxy_port))

    print()
    print("Ready. Press Ctrl+C to stop.")
    print()

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped.")
