import struct
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.database import get_session
from app.engine.pipeline import pipeline
from app.schemas.traffic import FlowBatchIn, FlowRecord, FlowIngestResponse

logger = get_logger("unishield.api.traffic")

router = APIRouter(prefix="/api/v1/traffic", tags=["traffic"])


@router.post("/flow", response_model=FlowIngestResponse)
async def ingest_flow(flow: FlowRecord) -> FlowIngestResponse:
    flow_id = await pipeline.submit(flow)
    if flow_id is None:
        return FlowIngestResponse(received=1, accepted=0, rejected=1, flow_ids=[])
    return FlowIngestResponse(received=1, accepted=1, rejected=0, flow_ids=[flow_id])


@router.post("/flows", response_model=FlowIngestResponse)
async def ingest_flow_batch(batch: FlowBatchIn) -> FlowIngestResponse:
    accepted_ids = await pipeline.submit_batch(batch.flows)
    return FlowIngestResponse(
        received=len(batch.flows),
        accepted=len(accepted_ids),
        rejected=len(batch.flows) - len(accepted_ids),
        flow_ids=accepted_ids,
    )


@router.get("/stats")
async def traffic_stats() -> dict:
    from app.state.connection_tracker import connection_tracker
    from app.utils.metrics import runtime_metrics

    return {
        "flows_queued": pipeline.queue_size,
        "active_flows": pipeline.flow_state.size(),
        "connections": connection_tracker.active_connections(),
        "processed": runtime_metrics.flows_processed,
        "window": "60s",
    }


@router.post("/replay")
async def replay_pcap(pcap_path: str) -> dict:
    try:
        from app.ingestion.scapy import ScapyParser

        parser = ScapyParser()
        records = parser.parse_pcap_file(pcap_path)
        accepted = await pipeline.submit_batch(records)
        return {"replayed": len(records), "accepted": len(accepted)}
    except Exception as exc:
        return {"replayed": 0, "accepted": 0, "error": str(exc)}


@router.post("/netflow")
async def ingest_netflow_export(payload: bytes = Body(...)) -> FlowIngestResponse:
    """Ingest a raw NetFlow/IPFIX/sFlow UDP datagram (PS input surface)."""
    from app.ingestion.netflow import parse_flow_export

    records = parse_flow_export(payload)
    accepted_ids = await pipeline.submit_batch(records)
    return FlowIngestResponse(
        received=len(records),
        accepted=len(accepted_ids),
        rejected=len(records) - len(accepted_ids),
        flow_ids=accepted_ids,
    )


@router.get("/flows")
async def list_flows(limit: int = 200) -> dict:
    """Return a serializable snapshot of recently active flows for the SOC UI."""
    try:
        now = datetime.now(timezone.utc).timestamp()
        snapshot = pipeline.flow_state.snapshot()
    except Exception:
        raise HTTPException(status_code=500, detail="flow_state unavailable")
    rows = []
    for entry in snapshot.values():
        periodicity = _estimate_periodicity(entry)
        rows.append(
            {
                "flow_id": entry.flow_id,
                "src_ip": entry.src_ip,
                "dst_ip": entry.dst_ip,
                "src_port": entry.src_port,
                "dst_port": entry.dst_port,
                "protocol": entry.protocol,
                "packet_count": entry.packet_count,
                "byte_count": entry.byte_count,
                "syn_count": entry.syn_count,
                "ack_count": entry.ack_count,
                "rst_count": entry.rst_count,
                "fin_count": entry.fin_count,
                "first_seen": entry.first_seen,
                "last_seen": entry.last_seen,
                "age_sec": round(now - entry.first_seen, 2),
                "periodicity": periodicity,
            }
        )
    rows.sort(key=lambda r: r["last_seen"], reverse=True)
    return {"count": len(rows), "limit": limit, "window": "60s", "flows": rows[:limit]}


def _estimate_periodicity(entry) -> float:
    """Crude C2-beacon indicator: 1.0 if inter-arrival gaps are near-constant."""
    ts = list(getattr(entry, "timestamps", None) or [])
    if len(ts) < 5:
        return 0.0
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(gaps) < 4:
        return 0.0
    mean = sum(gaps) / len(gaps)
    if mean <= 0.01:
        return 0.0
    variance = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    cv = variance ** 0.5 / mean
    return round(max(0.0, min(1.0, 1.0 - cv / 0.5)), 3)