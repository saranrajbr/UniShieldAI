"""Generate synthetic test traffic flows and forward them to the backend.

Used to exercise the detection pipeline without live capture.
"""

import argparse
import asyncio
import logging
import time
from typing import Any

import httpx

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("gen-traffic")

from app.ingestion.test_source import TestTrafficSource


async def send_batch(client: httpx.AsyncClient, url: str, batch: list[Any]) -> None:
    payload = {
        "sensor_id": "test-traffic-generator",
        "flows": [f.model_dump(mode="json") for f in batch],
    }
    try:
        response = await client.post(f"{url}/api/v1/traffic/flows", json=payload)
        response.raise_for_status()
        data = response.json()
        logger.info(
            "sent=%d accepted=%d rejected=%d",
            data.get("received", 0), data.get("accepted", 0), data.get("rejected", 0),
        )
    except Exception as exc:
        logger.error("send failed: %s", exc)


async def run(args: argparse.Namespace) -> None:
    source = TestTrafficSource(flows_per_second=args.fps, seed=args.seed)
    await source.start()

    base = args.url.rstrip("/")
    batch: list[Any] = []
    start = time.monotonic()

    async with httpx.AsyncClient(timeout=5.0) as client:
        async for record in source.read():
            if args.duration > 0 and time.monotonic() - start >= args.duration:
                break
            batch.append(record)
            if len(batch) >= args.batch_size:
                await send_batch(client, base, batch)
                batch = []
        if batch:
            await send_batch(client, base, batch)

    await source.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate test traffic for UniShield")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--fps", type=float, default=50.0)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--duration", type=float, default=0.0, help="seconds (0 = infinite)")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()