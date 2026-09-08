"""UniShield live capture sensor.

Captures mirrored traffic and forwards flow metadata to the FastAPI backend.
In production this relies on Zeek for structured flow generation; Scapy is
used for controlled testing/interfaces without Zeek.
"""

import asyncio

from app.ingestion.base import FlowSourceBase
from app.schemas.traffic import FlowRecord


class LiveCapture:
    def __init__(self, backend_url: str, source: FlowSourceBase,
                 batch_size: int = 100, flush_interval: float = 1.0) -> None:
        self.backend_url = backend_url
        self.source = source
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._running = False

    async def start(self) -> None:
        self._running = True
        await self.source.start()

    async def stop(self) -> None:
        self._running = False
        await self.source.stop()

    async def run(self) -> None:
        if not self._running:
            await self.start()
        batch: list[FlowRecord] = []
        async for record in self.source.read():
            batch.append(record)
            if len(batch) >= self.batch_size:
                await self._send(batch)
                batch = []
                await asyncio.sleep(self.flush_interval)
        if batch:
            await self._send(batch)

    async def _send(self, records: list[FlowRecord]) -> None:
        try:
            import httpx

            payload = {"sensor_id": "unishield-sensor",
                       "flows": [r.model_dump() for r in records]}
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{self.backend_url.rstrip('/')}/api/v1/traffic/flows", json=payload
                )
                response.raise_for_status()
        except Exception as exc:
            print(f"[sensor] failed to send {len(records)} flows: {exc}")