#!/usr/bin/env python3
"""WebSocket echo load: N connections each ping-ponging small masked frames.

  python3 bench/ws_load.py 127.0.0.1 8080 /ws/echo [conns=200] [seconds=10]

Needs an echoing upstream behind the route (scripts/mock-upstream.py works).
Prints messages/second and latency percentiles. Uses asyncio only (no deps).
"""
import asyncio, base64, os, struct, sys, time

HOST, PORT, PATH = sys.argv[1], int(sys.argv[2]), sys.argv[3]
CONNS = int(sys.argv[4]) if len(sys.argv) > 4 else 200
SECS = float(sys.argv[5]) if len(sys.argv) > 5 else 10.0
MSG = b"x" * 64

def frame(payload: bytes) -> bytes:  # masked text frame, payload < 126
    mask = os.urandom(4)
    return bytes([0x81, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

async def one(lat, stop):
    r, w = await asyncio.open_connection(HOST, PORT)
    key = base64.b64encode(os.urandom(16)).decode()
    w.write((f"GET {PATH} HTTP/1.1\r\nHost: b\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
             f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    head = await r.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 101"), head
    f = frame(MSG)
    while not stop.is_set():
        t = time.perf_counter()
        w.write(f)
        await r.readexactly(2 + len(MSG))   # unmasked echo: 2-byte header + payload
        lat.append(time.perf_counter() - t)
    w.close()

async def main():
    lat, stop = [], asyncio.Event()
    tasks = [asyncio.create_task(one(lat, stop)) for _ in range(CONNS)]
    await asyncio.sleep(SECS); stop.set()
    await asyncio.gather(*tasks, return_exceptions=True)
    lat.sort()
    if not lat: print("no samples"); return
    pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))] * 1e3
    print(f"{len(lat)/SECS:,.0f} msg/s  p50={pct(.5):.2f}ms p99={pct(.99):.2f}ms p99.9={pct(.999):.2f}ms ({CONNS} conns)")

asyncio.run(main())
