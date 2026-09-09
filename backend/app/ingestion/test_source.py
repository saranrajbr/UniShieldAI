"""Test traffic generation source.

Creates synthetic flow records resembling common cyber threats:
port scans, SYN floods / DDoS, brute force, and benign traffic.
These are used to exercise the detection pipeline without live capture.
"""

import asyncio
import random
from datetime import datetime, timedelta, timezone

from app.ingestion.base import FlowSourceBase
from app.schemas.traffic import FlowRecord

INTERNAL_PREFIX = "10.0.{segment}.{host}"
EXTERNAL_PREFIX = "{a}.{b}.{c}.{d}"

THREAT_SCENARIOS = {
    "port_scan": {"pct": 0.26, "label": "port_scan"},
    "syn_flood": {"pct": 0.07, "label": "syn_flood"},
    "udp_flood": {"pct": 0.05, "label": "udp_flood"},
    "slowloris": {"pct": 0.1, "label": "slowloris"},
    "dns_tunnel": {"pct": 0.12, "label": "dns_tunnel"},
    "c2_beacon": {"pct": 0.04, "label": "c2_beacon"},
    "brute_force": {"pct": 0.16, "label": "brute_force"},
    "benign": {"pct": 0.2, "label": "benign"},
}


class TestTrafficSource(FlowSourceBase):
    """Synthetic traffic source — named Test* but is NOT a pytest test class."""

    __test__ = False

    name = "test_source"

    def __init__(self, flows_per_second: float = 50.0, seed: int | None = None,
                 scenario: str | None = None) -> None:
        self.flows_per_second = flows_per_second
        self._rng = random.Random(seed)
        self._running = False
        self._seq = 0
        self._scenario_override = scenario if scenario in THREAT_SCENARIOS else None
        # Stable persona IPs so per-source state (unique_dst_ports,
        # connection_frequency, small_packet_ratio) actually accumulates the
        # way a real attacker's tool does, instead of a fresh IP per record.
        self._attacker = EXTERNAL_PREFIX.format(
            a=self._rng.randint(1, 223), b=self._rng.randint(0, 255),
            c=self._rng.randint(0, 255), d=self._rng.randint(1, 254),
        )
        self._victim = INTERNAL_PREFIX.format(segment=10, host=20)
        self._brute_victim = INTERNAL_PREFIX.format(segment=10, host=21)
        self._compromised = INTERNAL_PREFIX.format(segment=10, host=30)
        self._c2_server = f"233.51.{self._rng.randint(1, 254)}.{self._rng.randint(2, 254)}"
        self._scan_port = 1
        self._c2_port = self._rng.choice([443, 53, 8080])
        self._c2_src_port = self._rng.randint(1024, 65535)
        self._c2_ts_offset = 0.0

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False

    async def read(self):
        while self._running:
            records = self.generate_batch(int(self.flows_per_second))
            for record in records:
                if not self._running:
                    return
                yield record
            await asyncio.sleep(1.0)

    def generate_batch(self, count: int) -> list[FlowRecord]:
        records: list[FlowRecord] = []
        for _ in range(count):
            scenario = self._pick_scenario()
            records.append(self._scenario_record(scenario))
            self._seq += 1
        return records

    def _pick_scenario(self) -> str:
        if self._scenario_override is not None:
            return self._scenario_override
        total = sum(cfg["pct"] for cfg in THREAT_SCENARIOS.values())
        pick = self._rng.random() * total
        acc = 0.0
        for name, cfg in THREAT_SCENARIOS.items():
            acc += cfg["pct"]
            if pick <= acc:
                return name
        return "benign"

    def _scenario_record(self, scenario: str) -> FlowRecord:
        external_ip = self._attacker
        internal_ip = self._victim

        if scenario == "port_scan":
            # nmap-style sweep: one attacker, one victim, walking ports so the
            # same (src,dst) pair accumulates distinct dst ports.
            target = internal_ip
            port = self._scan_port
            self._scan_port = (self._scan_port % 2000) + 1
            return self._make(external_ip, target, port, "tcp",
                              packets=2, bytes_=80,
                              syn=1, ack=1, rst=0, fin=0)

        if scenario == "syn_flood":
            # Spoofed flood: fresh src per probe (classic hping3), steady
            # target so rate/source-entropy rules accumulate.
            syn = self._rng.randint(400, 1500)
            ack = self._rng.randint(0, 20)
            spoofed = EXTERNAL_PREFIX.format(
                a=self._rng.randint(1, 223), b=self._rng.randint(0, 255),
                c=self._rng.randint(0, 255), d=self._rng.randint(1, 254),
            )
            return self._make(spoofed, internal_ip, self._rng.choice([80, 443]),
                              "tcp", packets=syn + ack, bytes_=(syn + ack) * self._rng.randint(40, 80),
                              syn=syn, ack=ack, rst=0, fin=0)

        if scenario == "udp_flood":
            packets = self._rng.randint(500, 3000)
            spoofed = EXTERNAL_PREFIX.format(
                a=self._rng.randint(1, 223), b=self._rng.randint(0, 255),
                c=self._rng.randint(0, 255), d=self._rng.randint(1, 254),
            )
            return self._make(spoofed, internal_ip, self._rng.randint(5000, 65000),
                              "udp", packets=packets, bytes_=packets * self._rng.randint(64, 300),
                              syn=0, ack=0, rst=0, fin=0)

        if scenario == "slowloris":
            # Tiny half-open connections held open; not a raw SYN flood.
            packets = self._rng.randint(4, 60)
            return self._make(external_ip, internal_ip, 80, "tcp",
                              packets=packets, bytes_=packets * self._rng.randint(40, 250),
                              syn=1, ack=max(0, packets - 2), rst=0, fin=0)

        if scenario == "dns_tunnel":
            packets = self._rng.randint(50, 400)
            alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
            qname = ".".join(
                "".join(self._rng.choice(alphabet) for _ in range(self._rng.randint(18, 30)))
                for _ in range(self._rng.randint(4, 6))
            ) + ".t"
            record = self._make(self._compromised, external_ip, 53, "udp",
                              packets=packets, bytes_=packets * self._rng.randint(40, 120),
                              syn=0, ack=0, rst=0, fin=0)
            record.dns_query = qname
            return record

        if scenario == "c2_beacon":
            # Regular ~60s cadence on a fixed 5-tuple so periodicity builds;
            # timestamps are back-dated per beacon to simulate time passing.
            packets = self._rng.randint(20, 100)
            self._c2_ts_offset += 60.0
            record = self._make(self._compromised, self._c2_server, self._c2_port,
                              "tcp", packets=packets, bytes_=packets * self._rng.randint(60, 400),
                              syn=1, ack=packets - 1, rst=0, fin=0)
            record.src_port = self._c2_src_port
            record.ts = datetime.now(timezone.utc) - timedelta(seconds=self._c2_ts_offset)
            return record

        if scenario == "brute_force":
            # hydra-style: many small failed attempts to a dedicated SSH target
            # (separate victim so unique_dst_ports==1 for this (src,dst) pair).
            packets = self._rng.randint(6, 20)
            return self._make(external_ip, self._brute_victim, 22, "tcp",
                              packets=packets, bytes_=packets * self._rng.randint(80, 400),
                              syn=1, ack=max(0, packets - 2), rst=0, fin=1)

        # BENIGN — normal iperf3-like bulk HTTPS / web / DNS traffic.
        if self._rng.random() < 0.2:
            record = self._make(
                internal_ip if self._rng.random() > 0.5 else external_ip,
                external_ip if self._rng.random() > 0.5 else internal_ip,
                53, "udp",
                packets=self._rng.randint(1, 4),
                bytes_=self._rng.randint(60, 300),
                syn=0, ack=0, rst=0, fin=0,
            )
            record.dns_query = f"{self._rng.choice(['www','mail','api','cdn','app'])}.{self._rng.choice(['google','github','example','company'])}.{self._rng.choice(['com','net','org','io'])}"
            return record

        dst_port = self._rng.choice([80, 443, 443, 443])
        packets = self._rng.randint(5, 400)
        return self._make(
            internal_ip if self._rng.random() > 0.5 else external_ip,
            external_ip if self._rng.random() > 0.5 else internal_ip,
            dst_port, "tcp",
            packets=packets,
            bytes_=packets * self._rng.randint(400, 1400),
            syn=1, ack=max(0, packets - 2), rst=0,
            fin=1 if self._rng.random() > 0.7 else 0,
        )

    def _make(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str,
              packets: int, bytes_: int, syn: int, ack: int, rst: int, fin: int) -> FlowRecord:
        return FlowRecord(
            ts=datetime.now(timezone.utc),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=self._rng.randint(1024, 65535),
            dst_port=dst_port,
            protocol=protocol,
            packet_count=packets,
            byte_count=bytes_,
            syn_count=syn,
            ack_count=ack,
            rst_count=rst,
            fin_count=fin,
        )