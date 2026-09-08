# Implementation Plan — Router Link / Unidirectional Enclave Monitor

Status: **PLANNED — not executed.** This document records the changes required
to reframe UniShield from a "single-link / single-LAN monitor" into a
**gateway/peering router-link monitor in a passive, one-directional monitoring
enclave**, per Problem Statement **26145**.

The background and constraints of 26145 (read-only ingest via data
diode / SPAN mirror of the gateway link; NetFlow/IPFIX/sFlow + pcap as input;
no return path, no payload decryption, streaming alerts, standardized alert
schema) are already satisfied **architecturally** by the current engine. The
gaps are deliverables/framing. Each item below has a clear owner file and a
concrete change; none has been applied yet.

> When the user says "execute", apply these in order. Each section is an
> actionable step with verification.

---

## How the current system already fits 26145

| 26145 requirement | Current status |
|-------------------|----------------|
| (a) Read-only ingest; no return path / no inline block | ✅ Engine only consumes flows/pcap; never probes or blocks. |
| (b) No payload decryption; TLS/QUIC from metadata | ✅ Detection is flow-feature based; no decryption. |
| (c) Streaming, incremental, bounded-latency alerts | ✅ REST + `/ws` + `/ws/alerts` publish per-flow decisions. |
| (e) Standardized alert schema (timestamp, flow id, threat class, confidence, evidence) | ✅ `AlertOut` includes all of these. |
| Detect: DDoS, C2 beaconing, DGA/DNS tunnel, recon/scan, exfil | ✅ Rules + ML cover these classes. |

Reference frames in this doc:
- **Monitoring enclave** = Laptop 1 (backend / analytics, isolated, no path back to production).
- **Sensor / tap** = Laptop 2 (passive tap mirroring the router link). See `docs/vm-testing.md`, `docs/windows-setup.md`.
- **"Link being monitored"** = the internet-facing gateway/peering link, mirrored read-only into the enclave.

---

## Change 1 — Add a NetFlow / IPFIX / sFlow ingester

**Why:** 26145 explicitly lists "exported flow records (NetFlow/IPFIX/sFlow)"
as a supported input. Current ingest is flow-JSON (`POST /api/v1/traffic/flows`)
and pcap (`ScapyParser`). A router exporting flows to the enclave needs a
standard-format parser.

**Files:**
- New: `backend/app/ingestion/flow_export.py` — `NetFlowV5Parser`,
  `IPFIXParser`, `SFlowParser` (or a single `FlowExportParser` dispatching on
  version bytes / enterprise header).
- Edit: `backend/app/ingestion/__init__.py` — export the new parsers.
- Edit: `backend/app/api/traffic.py` — add ingest endpoints that accept
  raw NetFlow/sFlow/UDP datagrams and enqueue parsed `FlowRecord`s, e.g.
  `POST /api/v1/traffic/netflow`, `POST /api/v1/traffic/sflow`, and/or a UDP
  listener service.
- Optional: `backend/app/sensor/live_capture/` — a UDP listener that receives
  router exports and feeds `FlowStreamSource` / `LiveCapture`.
- New tests: `backend/tests/test_flow_export.py`.

**Acceptance:**
- A synthetic NetFlow v5 datagram, an IPFIX template+data set, and an sFlow
  datagram each parse into `FlowRecord`s with correct
  `src_ip/dst_ip/src_port/dst_port/protocol/packet_count/byte_count/ts`.
- End-to-end: submitted flow triggers the same alerts as the JSON path.

**Dependency:** none new required for parsing (pure construction); optional
`scapy` already present for raw frames.

---

## Change 2 — Document the throughput target (constraint d)

**Why:** 26145 requires the solution to state and demonstrate the traffic
rate it was tested against (flows/sec or Mbps sustained).

**Files:**
- Edit: `backend/README.md` — add a "Throughput / tested rate" section.
- Edit: `docs/deployment.md` — add a "Performance / throughput" subsection.
- Optionally add `backend/scripts/benchmark_ingest.py` to measure
  flows/sec sustained through `POST /api/v1/traffic/flows`.

**Content to provide (measured value is inferred; fill with the actual number
from a benchmark run):**
- Sustained `flows/sec` the engine processed with bounded queue depth.
- Sustained `Mbps` equivalent (average flow size × flows/sec).
- Config window: `ROLLING_WINDOW_SEC` / `PIPELINE_QUEUE_SIZE` / `MAX_CONCURRENT_FLOWS`.

**Acceptance:** README and deployment docs state the tested rate and how it
was measured.

---

## Change 3 — Reframe docs as a router-link / border enclave monitor

**Why:** The dashboards/docs currently describe a single LAN being watched.
26145 wants the *enclave* observing a *gateway/peering link*.

**Files / edits (documentation only; no engine change):**
- `docs/architecture.md` — add a short "Deployment = monitoring enclave"
  note: the flow sources (sFlow/IPFIX mirror, pcap tap, sensor VM) represent
  a passive mirror of the router link; the backend is the enclave.
- `docs/detection.md` — already maps lab scenarios to internet-facing
  attackers (hping3/tr/rex, Slowloris, dnscat2/iodine, DGA); add an explicit
  "border/gateway link" framing sentence.
- `docs/vm-testing.md` / `docs/windows-setup.md` — label Laptop 2 tap as
  "mirroring the router link", Laptop 1 as "enclave".
- `backend/README.md` — first paragraph: describe the system as monitoring a
  unidirectional gateway link tap/enclave (data-diode / SPAN), read-only.

**Acceptance:** Reading the docs, a reviewer sees the enclave + passive
mirror-of-router-link model, not a single-laptop monitor.

---

## Change 4 — Scenario mapping table already aligned (verify only)

**Why:** The problem statement's dataset list (iperf3/Ostinato/TRex benign;
hping3 SYN/UDP; Slowloris; dnscat2/iodine; DGA samples; sandboxed C2
emulator) maps to existing synthetic scenarios. This is documentation-only
verification, applied with Change 3.

**Files:** `docs/detection.md` "Scenario → detection mapping" table is the
single source; confirm lab-tool names (`Ostinato`, `TRex`, `DGArchive`,
`dnscat2`, `iodine`) appear next to the threat types.

---

## Change 5 — (Optional, deferred) Production-styled fingerprinting

**Why:** 26145 part (d) mentions JA3/JA3S/JA4 from TLS/QUIC metadata. The
current engine uses flow/feature detection, not cipher-string fingerprinting.
Not required to satisfy the base constraints; only add if extra guardrail
coverage is wanted.

**Files (new, not started):**
- `backend/app/features/tls.py` — parse TLS ClientHello from pcap to derive a
  JA3-like string.
- Wire into `ScapyParser`/flow record as an optional `tls_ja3` field.
- Add `tls_ja3` to the feature set (would require retraining if added to
  `FEATURE_COLUMNS` — **keep out of the ML vector** to avoid retraining; use
  it as a rule input only).

**Acceptance (if executed):** a TLS flow yields a JA3 string surfaced in
evidence. NOT needed for the main deliverable.

---

## Execution order (when the user says "go")

1. **Change 1** (ingester) + tests — code.
2. **Change 2** (throughput) — run a benchmark, document the number.
3. **Change 3 + 4** (docs framing / scenario table) — documentation edits.
4. **Change 5** (JA3) — only if requested.

Each change should be committed separately per the repo's preference (the
user handles git staging).

## Notes / risks
- Adding `tls_ja3` to `FEATURE_COLUMNS` would invalidate trained models;
  Change 5 deliberately avoids that by staying a rule-only input.
- The NetFlow/sFlow endpoint must trust the mirrored stream boundary — no
  authentication over the wire in a lab; document that the enclave boundary
  provides the trust, matching the data-diode model (read-only, no return
  path).