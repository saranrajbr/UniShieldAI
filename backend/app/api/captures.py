import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from app.alerts.evidence import EvidenceCollector
from app.core.config import settings
from app.core.logging import get_logger
from app.capture.flow_pcap import flow_pcap_recorder

logger = get_logger("unishield.api.captures")

router = APIRouter(prefix="/api/v1/captures", tags=["captures"])

_internal = {"active/": Path(settings.pcap_active_path).parent}


def _allowed(name: str) -> Path:
    """Resolve a capture filename to a safe absolute path inside captures/."""
    base = Path("captures").resolve()
    path = (base / name).resolve()
    if base not in path.parents:
        raise HTTPException(status_code=400, detail="Invalid capture path")
    return path


@router.get("/incidents")
async def list_incidents() -> dict:
    collector = EvidenceCollector()
    files = []
    for p in collector.incident_files():
        files.append({
            "name": p.name,
            "path": str(p),
            "size": p.stat().st_size,
            "mtime": p.stat().st_mtime,
        })
    return {"total": len(files), "files": files}


@router.get("/active")
async def active_capture() -> dict:
    path = flow_pcap_recorder.current_path()
    return {
        "path": str(path),
        "exists": flow_pcap_recorder.active_exists(),
        "size": path.stat().st_size if path.exists() else 0,
        "mtime": path.stat().st_mtime if path.exists() else 0,
    }


@router.get("/download")
async def download_capture(file: str = Query(...)) -> FileResponse:
    path = _allowed(file)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Capture not found")
    return FileResponse(str(path), filename=path.name)


@router.get("/packets")
async def packets(
    file: str = Query("active/current.pcap"),
    limit: int = Query(200, ge=1, le=2000),
) -> dict:
    if file == "active/current.pcap":
        path = flow_pcap_recorder.current_path()
    else:
        path = _allowed(file)
    if not path.exists() or path.stat().st_size == 0:
        return {"total": 0, "packets": []}

    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP
    except ImportError:
        return {"error": "scapy unavailable", "total": 0, "packets": []}

    try:
        packets = rdpcap(str(path))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return {"error": str(exc), "total": 0, "packets": []}

    view = []
    for pkt in packets[:limit]:
        entry = {
            "time": float(getattr(pkt, "time", 0.0)),
            "src": "-",
            "dst": "-",
            "proto": "?",
            "sport": None,
            "dport": None,
            "len": len(pkt),
            "flags": "",
            "summary": str(pkt.summary()),
        }
        if pkt.haslayer(IP):
            entry["src"] = pkt[IP].src
            entry["dst"] = pkt[IP].dst
            entry["proto"] = "tcp" if pkt.haslayer(TCP) else ("udp" if pkt.haslayer(UDP) else "icmp")
            if pkt.haslayer(TCP):
                entry["sport"] = pkt[TCP].sport
                entry["dport"] = pkt[TCP].dport
                entry["flags"] = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                entry["sport"] = pkt[UDP].sport
                entry["dport"] = pkt[UDP].dport
        raw = bytes(pkt)
        entry["hex"] = raw.hex()
        entry["raw_len"] = len(raw)
        entry["decode"] = _decode_packet(pkt)
        view.append(entry)
    return {"total": len(packets), "packets": view}


def _decode_packet(pkt) -> dict:
    """Wireshark-style tree for the IP/TCP/UDP/ICMP headers of a packet."""
    tree: dict = {}
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    if pkt.haslayer(IP):
        ip = pkt[IP]
        tree["ip"] = {
            "version": int(ip.version),
            "ihl": int(ip.ihl),
            "tos": int(ip.tos),
            "ttl": int(ip.ttl),
            "protocol": int(ip.proto),
            "header_len_bytes": int(ip.ihl) * 4,
            "src": ip.src,
            "dst": ip.dst,
        }
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        tree["tcp"] = {
            "src_port": int(t.sport),
            "dst_port": int(t.dport),
            "seq": int(t.seq),
            "ack": int(t.ack),
            "data_offset": int(t.dataofs),
            "flags": str(t.flags),
            "window": int(t.window),
            "checksum": hex(int(t.chksum)) if t.chksum is not None else None,
        }
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        tree["udp"] = {
            "src_port": int(u.sport),
            "dst_port": int(u.dport),
            "length": int(u.len),
            "checksum": hex(int(u.chksum)) if u.chksum is not None else None,
        }
    elif pkt.haslayer(ICMP):
        c = pkt[ICMP]
        tree["icmp"] = {
            "type": int(c.type),
            "code": int(c.code),
            "checksum": hex(int(c.chksum)) if c.chksum is not None else None,
        }
    payload = bytes(pkt.getlayer(IP).payload) if pkt.haslayer(IP) else bytes(pkt.payload)
    tree["payload_len"] = len(payload)
    if payload:
        printable = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[:128])
        tree["payload_preview"] = printable
    return tree