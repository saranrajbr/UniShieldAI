import asyncio
from collections.abc import AsyncIterator

from app.ingestion.base import FlowSourceBase
from app.ingestion.flow_parser import FlowParser
from app.schemas.traffic import FlowRecord


class FlowStreamSource(FlowSourceBase):
    """Reads flow records line by line from an async stream (e.g. stdin, socket, HTTP body)."""

    name = "stream"

    def __init__(self, parser: FlowParserBase | None = None) -> None:
        from app.ingestion.base import FlowParserBase
        self.parser: FlowParserBase = parser or FlowParser()
        self._queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=10000)
        self._running = False
        self._consumer: asyncio.Task | None = None

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False
        if self._consumer:
            self._consumer.cancel()

    async def feed_line(self, line: str) -> None:
        await self._queue.put(line.encode("utf-8"))

    async def feed_payload(self, payload: bytes) -> None:
        for record in self.parser.parse_payload(payload):
            await self._queue.put(record)

    async def read(self) -> AsyncIterator[FlowRecord]:
        while True:
            item = await self._queue.get()
            if isinstance(item, bytes):
                text = item.decode("utf-8", errors="ignore")
                record = self.parser.parse_line(text)
                if record is not None:
                    yield record
            elif isinstance(item, FlowRecord):
                yield item
            else:
                yield item


class AsyncLineBuffer:
    def __init__(self, max_chunk: int = 65536) -> None:
        self._buffer = ""
        self._max_chunk = max_chunk

    def ingest(self, chunk: str) -> list[str]:
        self._buffer += chunk
        lines = self._buffer.split("\n")
        self._buffer = lines.pop()
        return lines

    def flush(self) -> str:
        remainder, self._buffer = self._buffer, ""
        return remainder