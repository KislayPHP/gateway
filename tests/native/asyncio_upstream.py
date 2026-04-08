#!/usr/bin/env python3
import argparse
import asyncio


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            try:
                raw = await reader.readuntil(b"\r\n\r\n")
            except asyncio.IncompleteReadError:
                break

            header_block = raw.decode("latin1")
            lines = header_block.split("\r\n")
            if not lines or not lines[0]:
                break
            parts = lines[0].split(" ", 2)
            if len(parts) < 2:
                break
            path = parts[1]
            content_length = 0
            keep_alive = True
            for line in lines[1:]:
                if not line:
                    continue
                lower = line.lower()
                if lower.startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
                elif lower.startswith("connection:") and "close" in lower:
                    keep_alive = False

            if content_length:
                await reader.readexactly(content_length)

            if path == "/slow":
                await asyncio.sleep(0.05)

            body = f"upstream-ok:{path}".encode("utf-8")
            headers = [
                b"HTTP/1.1 200 OK",
                f"Content-Length: {len(body)}".encode("ascii"),
                b"Content-Type: text/plain",
                b"Connection: keep-alive" if keep_alive else b"Connection: close",
                b"",
                b"",
            ]
            writer.write(b"\r\n".join(headers) + body)
            await writer.drain()

            if not keep_alive:
                break
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19091)
    args = parser.parse_args()

    server = await asyncio.start_server(handle_client, args.host, args.port, reuse_address=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
