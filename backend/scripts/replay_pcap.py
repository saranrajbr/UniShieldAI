"""Replay a PCAP file into the UniShield detection backend.

Parses the PCAP into flow records via Scapy and POSTs them to the pipeline.
"""

import argparse
import asyncio
import logging
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("replay")


async def replay(pcap_path: str, url: str, batch_size: int) -> None:
    from app.ingestion.scapy import ScapyParser

    parser = ScapyParser()
    records = parser.parse_pcap_file(pcap_path)
    logger.info("Parsed %d flow records from %s", len(records), pcap_path)

    base = url.rstrip("/")
    async with httpx.AsyncClient(timeout=10.0) as client:
        for i in range(0, len(records), batch_size):
            chunk = records[i : i + batch_size]
            payload = {"sensor_id": "pcap-replay", "flows": [r.model_dump(mode="json") for r in chunk]}
            response = await client.post(f"{base}/api/v1/traffic/flows", json=payload)
            response.raise_for_status()
            data = response.json()
            logger.info(
                "batch %d: sent=%d accepted=%d",
                i // batch_size, data.get("received"), data.get("accepted"),
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay a PCAP into UniShield")
    parser.add_argument("pcap_path", type=str)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()

    if not Path(args.pcap_path).exists():
        logger.error("PCAP not found: %s", args.pcap_path)
        return
    asyncio.run(replay(args.pcap_path, args.url, args.batch_size))


if __name__ == "__main__":
    main()