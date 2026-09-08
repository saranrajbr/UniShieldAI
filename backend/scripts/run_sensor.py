"""Run the live-capture sensor against the UniShield backend.

Sniffs mirrored lab traffic on a tap/SPAN interface (Scapy), turns it into
flow records, and POSTs them to the backend over the WireGuard tunnel.

Run on Laptop 2 inside the uni-shield sensor VM:

    PYTHONPATH=$PWD:../sensor:/tmp/opencode/ush_venv/lib/python3.13/site-packages \
        python scripts/run_sensor.py --iface enp0s8 --url http://172.16.250.1:8000

Or via the helper wrapper:
    ./scripts/run-sensor.sh -i enp0s8 -u http://172.16.250.1:8000
"""

import argparse
import asyncio

from app.ingestion.base import FlowSourceBase
from app.ingestion.scapy_live import ScapyLiveSource
from sensor.live_capture.capture import LiveCapture


async def main(iface: str, url: str, batch: int, interval: float) -> None:
    source: FlowSourceBase = ScapyLiveSource(iface)
    capture = LiveCapture(backend_url=url, source=source,
                          batch_size=batch, flush_interval=interval)
    try:
        await capture.run()
    except KeyboardInterrupt:
        await capture.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="UniShield live sensor (Laptop 2)")
    parser.add_argument("--iface", "-i", required=True, help="tap/SPAN interface to sniff")
    parser.add_argument("--url", "-u", default="http://172.16.250.1:8000",
                        help="Laptop 1 backend base URL")
    parser.add_argument("--batch", type=int, default=100)
    parser.add_argument("--interval", type=float, default=1.0)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    asyncio.run(main(args.iface, args.url, args.batch, args.interval))