"""UDP listener for router flow exports (NetFlow/IPFIX/sFlow).

Runs a datagram endpoint on `settings.netflow_udp_port` and feeds every
parsed FlowRecord into the detection pipeline, so a router SPAN/export on
the unidirectional link arrives on the exact same analysis path as sensor
batches. Template state for NetFlow v9/IPFIX persists across datagrams.
"""

import asyncio
from typing import Optional

from app.core.config import settings
from app.core.logging import get_logger
from app.engine.pipeline import pipeline
from app.ingestion.netflow import PersistentFlowExportDecoder

logger = get_logger("unishield.ingest.netflow_listener")


class FlowExportListener:
    def __init__(self, host: str = "", port: int = 0) -> None:
        self.host = host or settings.netflow_udp_host
        self.port = port or settings.netflow_udp_port
        self._decoder = PersistentFlowExportDecoder()
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._processing: Optional[asyncio.Task] = None
        self._queue: asyncio.Queue[bytes] | None = None
        self.received = 0
        self.parsed = 0
        self.rejected = 0

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=10000)
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _DatagramHandler(self),
            local_addr=(self.host, self.port),
        )
        self._processing = asyncio.create_task(self._process_loop(), name="netflow-consumer")
        logger.info("Flow export listener on udp://%s:%s", self.host, self.port)

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
        if self._processing:
            self._processing.cancel()
            try:
                await self._processing
            except asyncio.CancelledError:
                pass

    def enqueue(self, data: bytes) -> None:
        self.received += 1
        if self._queue is None:
            return
        try:
            self._queue.put_nowait(data)
        except asyncio.QueueFull:
            self.rejected += 1

    async def _process_loop(self) -> None:
        while True:
            data = await self._queue.get()
            try:
                records = await asyncio.to_thread(self._decoder.decode, data)
                if records:
                    await pipeline.submit_batch(records)
                    self.parsed += len(records)
            except Exception:
                self.rejected += 1
                logger.exception("Failed to ingest flow export datagram")
            finally:
                self._queue.task_done()

    def stats(self) -> dict:
        return {
            "udp_host": self.host,
            "udp_port": self.port,
            "datagrams_received": self.received,
            "records_parsed": self.parsed,
            "records_rejected": self.rejected,
        }


class _DatagramHandler(asyncio.DatagramProtocol):
    def __init__(self, listener: FlowExportListener) -> None:
        self.listener = listener

    def datagram_received(self, data: bytes, addr) -> None:
        self.listener.enqueue(data)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP socket error: %s", exc)


flow_export_listener = FlowExportListener()