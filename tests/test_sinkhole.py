"""Tests for the fake-internet sinkhole.

Uses ephemeral high ports so the suite runs without root. Exercises the real
UDP/TCP listeners end-to-end, plus the DNS packet (de)serialisation directly.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sinkhole  # noqa: E402


def _build_query(name: str, qtype: int = 1) -> bytes:
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    q = b""
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode("ascii")
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return header + q


def test_parse_dns_question_roundtrip():
    q = _build_query("evil.example.com", qtype=1)
    name, qtype, qclass = sinkhole.parse_dns_question(q)
    assert name == "evil.example.com"
    assert qtype == 1
    assert qclass == 1


def test_parse_dns_question_rejects_short():
    with pytest.raises(ValueError):
        sinkhole.parse_dns_question(b"\x00\x01")


def test_build_dns_response_a_record_points_at_answer_ip():
    q = _build_query("c2.malware.test", qtype=1)
    resp = sinkhole.build_dns_response(q, "192.168.56.1")
    # Transaction id preserved.
    assert resp[:2] == q[:2]
    # One answer, response bit set.
    ancount = struct.unpack(">H", resp[6:8])[0]
    assert ancount == 1
    # Last 4 bytes are the A record payload.
    assert resp[-4:] == socket.inet_aton("192.168.56.1")


def test_build_dns_response_non_a_has_no_answer():
    q = _build_query("c2.malware.test", qtype=28)  # AAAA
    resp = sinkhole.build_dns_response(q, "192.168.56.1")
    ancount = struct.unpack(">H", resp[6:8])[0]
    assert ancount == 0


@pytest.fixture
def running_sink():
    sink = sinkhole.Sinkhole(
        answer_ip="192.168.56.1",
        bind_ip="127.0.0.1",
        dns_port=0,       # ephemeral
        http_port=0,
        https_port=0,     # skip TLS in the integration test
        tcp_ports=[0],
        enable_https=False,
    )
    sink.start()
    time.sleep(0.1)
    yield sink
    sink.stop()


def test_dns_server_answers_over_the_wire(running_sink):
    ports = running_sink.actual_ports()
    dns_port = ports["dns"]
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3.0)
    try:
        client.sendto(_build_query("beacon.evil.test"), ("127.0.0.1", dns_port))
        data, _ = client.recvfrom(512)
    finally:
        client.close()
    name, qtype, _ = sinkhole.parse_dns_question(data)
    assert name == "beacon.evil.test"
    assert data[-4:] == socket.inet_aton("192.168.56.1")
    # The lookup was logged.
    assert any(r["proto"] == "dns" and r.get("qname") == "beacon.evil.test"
               for r in running_sink.log.records)


def test_http_server_returns_200_and_logs(running_sink):
    port = running_sink.actual_ports()["http"]
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3.0)
    try:
        client.connect(("127.0.0.1", port))
        client.sendall(b"GET /payload.bin HTTP/1.1\r\nHost: cdn.evil.test\r\n\r\n")
        resp = client.recv(4096)
    finally:
        client.close()
    assert b"200 OK" in resp
    time.sleep(0.1)
    assert any(r["proto"] == "http" and r.get("host") == "cdn.evil.test"
               for r in running_sink.log.records)


def test_raw_tcp_accept_and_log(running_sink):
    # The ephemeral tcp listener is whatever got assigned to tcp_ports[0].
    tcp_port = None
    for server in running_sink._servers:
        if isinstance(server, sinkhole.SinkTcpServer) and server.proto == "tcp":
            tcp_port = server.server_address[1]
    assert tcp_port is not None
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(3.0)
    try:
        client.connect(("127.0.0.1", tcp_port))
        client.sendall(b"\xde\xad\xbe\xef beacon")
    finally:
        client.close()
    time.sleep(0.2)
    assert any(r["proto"] == "tcp" and r.get("bytes", 0) > 0
               for r in running_sink.log.records)


def test_log_writes_jsonl(tmp_path):
    log_file = tmp_path / "sink.jsonl"
    log = sinkhole.EventLog(str(log_file), quiet=True)
    log.record("dns", "192.168.56.101", {"qname": "x.test"})
    log.close()
    lines = log_file.read_text().strip().splitlines()
    assert len(lines) == 1
    import json
    entry = json.loads(lines[0])
    assert entry["proto"] == "dns"
    assert entry["qname"] == "x.test"
    assert entry["src"] == "192.168.56.101"
