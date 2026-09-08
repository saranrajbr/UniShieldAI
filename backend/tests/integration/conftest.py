import os
import tempfile

os.environ.setdefault("DEBUG", "false")
os.environ.setdefault(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{tempfile.mkdtemp()}/test.db",
)

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.db.database import init_db
from app.engine.pipeline import pipeline
from app.main import app


@pytest_asyncio.fixture(autouse=True)
async def setup_backend():
    await init_db()
    await pipeline.start()
    yield
    await pipeline.stop()


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c