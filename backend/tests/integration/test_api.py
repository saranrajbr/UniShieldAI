import pytest


@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_ingest_flow(client):
    payload = {
        "src_ip": "8.8.8.8",
        "dst_ip": "10.0.0.1",
        "src_port": 5000,
        "dst_port": 80,
        "protocol": "tcp",
        "packet_count": 10,
        "byte_count": 1200,
    }
    response = await client.post("/api/v1/traffic/flow", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["received"] == 1
    assert body["accepted"] == 1


@pytest.mark.asyncio
async def test_live_alerts(client):
    response = await client.get("/api/v1/alerts/live")
    assert response.status_code == 200
    assert response.json()["total"] >= 0