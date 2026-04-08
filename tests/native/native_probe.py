#!/usr/bin/env python3
import argparse
import asyncio
import sys


async def one_client(host: str, port: int, path: str, expected: bytes, rounds: int, idx: int) -> str | None:
    reader, writer = await asyncio.open_connection(host, port)
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode("ascii")
    try:
        for _ in range(rounds):
            writer.write(request)
            await writer.drain()
            header = await reader.readuntil(b"\r\n\r\n")
            status = header.split(b"\r\n", 1)[0]
            if status != b"HTTP/1.1 200 OK":
                return f"client {idx}: bad status {status!r}"
            content_length = None
            for line in header.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":", 1)[1].strip())
                    break
            if content_length is None:
                return f"client {idx}: missing content-length"
            body = await reader.readexactly(content_length)
            if body != expected:
                return f"client {idx}: bad body {body!r}"
        writer.close()
        await writer.wait_closed()
        return None
    except Exception as exc:
        return f"client {idx}: {exc}"


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19090)
    parser.add_argument("--path", required=True)
    parser.add_argument("--expect-body", required=True)
    parser.add_argument("--clients", type=int, default=50)
    parser.add_argument("--rounds", type=int, default=20)
    args = parser.parse_args()

    expected = args.expect_body.encode("utf-8")
    results = await asyncio.gather(*[
        one_client(args.host, args.port, args.path, expected, args.rounds, i)
        for i in range(args.clients)
    ])
    errors = [result for result in results if result]
    print(f"errors={len(errors)}")
    for error in errors[:20]:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
