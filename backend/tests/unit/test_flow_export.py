import struct
from datetime import datetime, timezone

import pytest

from app.ingestion.netflow import (
    IPFIXParser,
    NetFlowV5Parser,
    NetFlowV9Parser,
    SFlowParser,
    parse_flow_export,
)


def _netflow_v5_datagram() -> bytes:
    """One NetFlow v5 datagram with two UDP flows."""
    header = struct.pack(">HHIIIIBBH", 5, 2, 1000, 1_700_000_000, 0, 1, 0, 1, 0)
    records = b""
    # flow 1: 192.168.1.10:1234 -> 10.0.0.5:53, UDP 17, 40 packets / 4000 bytes
    records += struct.pack(
        ">4s4s4sHHIIIIHHBBBBHHBBH",
        bytes([192, 168, 1, 10]),
        bytes([10, 0, 0, 5]),
        b"\x00\x00\x00\x00",
        1, 2,
        40, 4000,
        0, 0,
        1234, 53,
        0, 0x00, 17, 0,
        0, 0, 0, 0, 0,
    )
    # flow 2: 10.0.0.5:53 -> 192.168.1.10:5353, TCP 6, SYN+ACK flags
    records += struct.pack(
        ">4s4s4sHHIIIIHHBBBBHHBBH",
        bytes([10, 0, 0, 5]),
        bytes([192, 168, 1, 10]),
        b"\x00\x00\x00\x00",
        2, 1,
        12, 1200,
        0, 0,
        53, 5353,
        0, 0x12, 6, 0,
        0, 0, 0, 0, 0,
    )
    return header + records


class TestNetFlowV5:
    def test_parses_records(self):
        records = NetFlowV5Parser().parse(_netflow_v5_datagram())
        assert len(records) == 2
        r = records[0]
        assert r.src_ip == "192.168.1.10"
        assert r.dst_ip == "10.0.0.5"
        assert r.dst_port == 53
        assert r.protocol == "udp"
        assert r.packet_count == 40
        assert r.byte_count == 4000

    def test_tcp_flags_decoded(self):
        records = NetFlowV5Parser().parse(_netflow_v5_datagram())
        tcp = records[1]
        assert tcp.protocol == "tcp"
        assert tcp.syn_count == 1
        assert tcp.ack_count == 1

    def test_dispatch(self):
        records = parse_flow_export(_netflow_v5_datagram())
        assert len(records) == 2


class TestNetFlowV9:
    def test_template_plus_data(self):
        # v9 header
        header = struct.pack(">HHIIII", 9, 2, 1000, 1_700_000_000, 1, 0)
        # template set (set id 0): template 256 with 5 fields
        template_fields = struct.pack(">HH", 256, 5)
        spec = b"".join(
            struct.pack(">HH", t, l)
            for t, l in [
                (12, 4),  # srcIPv4
                (15, 4),  # dstIPv4
                (11, 2),  # srcPort
                (14, 2),  # dstPort
                (7, 1),  # protocol
            ]
        )
        set_len = 4 + 4 + len(spec)
        template_set = struct.pack(">HH", 0, set_len) + template_fields + spec
        # data set referencing template 256: one record
        rec = struct.pack(
            ">4s4sHHB",
            bytes([172, 16, 5, 2]),
            bytes([172, 16, 5, 1]),
            443, 54500, 6,
        )
        data_set = struct.pack(">HH", 256, 4 + len(rec)) + rec
        records = NetFlowV9Parser().parse(header + template_set + data_set)
        assert len(records) == 1
        assert records[0].src_ip == "172.16.5.2"
        assert records[0].dst_port == 54500
        assert records[0].protocol == "tcp"


class TestIPFIX:
    def test_ipfix_v10(self):
        header = struct.pack(">HHIII", 10, 0, 1_700_000_000, 1, 0)
        template_fields = struct.pack(">HH", 300, 6)
        spec = b"".join(
            struct.pack(">HH", t, l)
            for t, l in [
                (12, 4), (15, 4), (11, 2), (14, 2), (7, 1), (2, 4),
            ]
        )
        template_set = (
            struct.pack(">HH", 2, 4 + 4 + len(spec)) + template_fields + spec
        )
        rec = struct.pack(
            ">4s4sHHBI",
            bytes([10, 1, 1, 1]),
            bytes([10, 1, 1, 254]),
            8000, 443, 17, 120,
        )
        data_set = struct.pack(">HH", 300, 4 + len(rec)) + rec
        records = IPFIXParser().parse(header + template_set + data_set)
        assert len(records) == 1
        assert records[0].src_ip == "10.1.1.1"
        assert records[0].packet_count == 120


class TestSFlow:
    def test_flow_sample_socket4(self):
        # sFlow v5 datagram header: version(4) agent(4) subagent(4) seq(4) uptime(4) num_samples(4)
        head = struct.pack(">IIIIII", 5, 0x01010101, 0, 1, 100, 1)
        # flow sample body: sequence(4) source_id(4) sampling_rate(4) pool(4)
        #   drops(4) input(4) output(4) num_records(4)
        fs_body = struct.pack(">IIIIIIII", 1, 1000, 1000, 0, 0, 0, 0, 1)
        # one extended_socket4 record (format 3, 16 bytes):
        #   src_ip(4) dst_ip(4) src_port(2) dst_port(2) tcp_flags(1) proto(1) tos(1) pad(1)
        rec = struct.pack(
            ">4s4sHHBBBB",
            bytes([192, 168, 2, 2]),
            bytes([192, 168, 2, 1]),
            1234, 53,
            0x00, 17, 0, 0,
        )
        flow_sample = struct.pack(">II", 1, len(fs_body) + 8 + len(rec)) + fs_body
        flow_sample += struct.pack(">II", 3, len(rec)) + rec
        records = parse_flow_export(head + flow_sample)
        assert len(records) == 1
        assert records[0].src_ip == "192.168.2.2"
        assert records[0].dst_ip == "192.168.2.1"
        assert records[0].dst_port == 53
        assert records[0].protocol == "udp"