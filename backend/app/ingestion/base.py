import abc
from collections.abc import AsyncIterator

from app.schemas.traffic import FlowRecord


class IngestionError(Exception):
    def __init__(self, message: str, source: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.source = source


class FlowSourceBase(abc.ABC):
    name: str = "base"

    @abc.abstractmethod
    async def read(self) -> AsyncIterator[FlowRecord]:
        yield  # pragma: no cover

    @abc.abstractmethod
    async def start(self) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def stop(self) -> None:
        raise NotImplementedError


class FlowParserBase(abc.ABC):
    format_name: str = "base"

    @abc.abstractmethod
    def parse_line(self, line: str) -> FlowRecord | None:
        raise NotImplementedError

    @abc.abstractmethod
    def parse_payload(self, payload: bytes) -> list[FlowRecord]:
        raise NotImplementedError