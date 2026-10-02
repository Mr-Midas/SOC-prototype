#!/usr/bin/env python3
"""Arbiterion fake-internet sinkhole.

Runs on the HOST, bound to the host-only adapter (default 192.168.56.1), so a
detonated sample on the isolated analysis VM resolves and connects to the
sinkhole instead of hitting a dead network. Without this, samples abort on
their first failed connectivity check and you only observe the pre-network
behaviour. With it, DNS resolves, HTTP(S) returns a benign 200, and arbitrary
TCP ports accept-and-log, so a second stage / beacon has somewhere to go and
you capture the attempt.

Everything is answered locally; nothing is forwarded upstream. Every request is
appended to a JSONL log so the detonation report can show what the sample tried
to reach.

Design goals:
  * No third-party dependencies for DNS / HTTP / raw TCP (stdlib only).
  * HTTPS is best-effort: it needs a self-signed cert. If `cryptography` or the
    `openssl` CLI is available we mint one at startup; otherwise HTTPS is
    skipped with a logged warning and the rest of the sinkhole still runs.
  * Ports are fully configurable so the server can be unit-tested on high
    ports without root.

Usage (host, Administrator/root to bind 53/80/443):
    python scripts/sinkhole.py --answer-ip 192.168.56.1 --log sink.jsonl
    python scripts/sinkhole.py --duration 120            # auto-stop after 2 min
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_ANSWER_IP = "192.168.56.1"
# Common C2 / payload ports to accept-and-log in addition to 80/443.
DEFAULT_TCP_PORTS = [8080, 8443, 4444, 1337, 6667, 9001]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class EventLog:
    """Thread-safe JSONL connection log, also echoed to stdout."""

    def __init__(self, path: Optional[str], quiet: bool = False) -> None:
        self._lock = threading.Lock()
        self._fh = open(path, "a", encoding="utf-8") if path else None
        self._quiet = quiet
        self.records: list[dict] = []

    def record(self, proto: str, src: str, detail: dict) -> None:
        entry = {"ts": _now(), "proto": proto, "src": src, **detail}
        with self._lock:
            self.records.append(entry)
            if self._fh:
                self._fh.write(json.dumps(entry) + "\n")
                self._fh.flush()
            if not self._quiet:
                print(f"[sinkhole] {proto:5} {src:<21} {detail}", flush=True)

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None


# --------------------------------------------------------------------------- DNS


def parse_dns_question(data: bytes) -> tuple[str, int, int]:
    """Return (qname, qtype, qclass) from a DNS query. Raises on malformed input."""
    if len(data) < 12:
        raise ValueError("short DNS packet")
    offset = 12
    labels = []
    while True:
        if offset >= len(data):
            raise ValueError("truncated QNAME")
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:  # compression pointer not expected in a question
            raise ValueError("unexpected compression in question")
        labels.append(data[offset : offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(data):
        raise ValueError("missing QTYPE/QCLASS")
    qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
    return ".".join(labels), qtype, qclass


def build_dns_response(query: bytes, answer_ip: str) -> bytes:
    """Build an A-record response pointing every name at answer_ip.

    For A queries (type 1) we answer with answer_ip. For anything else we return
    a NOERROR response with no answers (so the resolver doesn't hang), which is
    enough to keep most samples moving.
    """
    txn_id = query[:2]
    qname, qtype, _qclass = parse_dns_question(query)
    # Question section as-is (everything after the 12-byte header).
    question = query[12:]
    header_flags = b"\x81\x80"  # standard query response, no error, recursion avail
    qdcount = b"\x00\x01"

    if qtype == 1:  # A
        ancount = b"\x00\x01"
        # Name pointer to the question (0xC00C), type A, class IN, TTL 60, len 4.
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4)
        answer += socket.inet_aton(answer_ip)
    else:
        ancount = b"\x00\x00"
        answer = b""

    header = txn_id + header_flags + qdcount + ancount + b"\x00\x00\x00\x00"
    return header + question + answer


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        server: "DnsServer" = self.server  # type: ignore[assignment]
        try:
            qname, qtype, _ = parse_dns_question(data)
        except ValueError as exc:
            server.log.record("dns", self.client_address[0], {"error": str(exc)})
            return
        try:
            resp = build_dns_response(data, server.answer_ip)
            sock.sendto(resp, self.client_address)
        except Exception as exc:  # noqa: BLE001 - never let the sinkhole crash
            server.log.record("dns", self.client_address[0], {"qname": qname, "error": str(exc)})
            return
        server.log.record(
            "dns",
            self.client_address[0],
            {"qname": qname, "qtype": qtype, "answer": server.answer_ip if qtype == 1 else None},
        )


class DnsServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, addr, answer_ip: str, log: EventLog) -> None:
        super().__init__(addr, DnsHandler)
        self.answer_ip = answer_ip
        self.log = log


# -------------------------------------------------------------------------- HTTP


class _HttpTcpHandler(socketserver.BaseRequestHandler):
    """Minimal HTTP responder that logs the request line + Host header."""

    def handle(self) -> None:
        server: "SinkTcpServer" = self.server  # type: ignore[assignment]
        conn = self.request
        conn.settimeout(5.0)
        try:
            raw = conn.recv(8192)
        except (socket.timeout, OSError):
            raw = b""
        request_line = ""
        host = ""
        if raw:
            text = raw.decode("latin-1", "replace")
            lines = text.split("\r\n")
            request_line = lines[0] if lines else ""
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break
        body = b"OK\n"
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        try:
            conn.sendall(response)
        except OSError:
            pass
        server.log.record(
            server.proto,
            self.client_address[0],
            {"port": server.server_address[1], "request": request_line, "host": host},
        )


class _RawTcpHandler(socketserver.BaseRequestHandler):
    """Accept-and-log handler for arbitrary TCP ports (beacon sink)."""

    def handle(self) -> None:
        server: "SinkTcpServer" = self.server  # type: ignore[assignment]
        conn = self.request
        conn.settimeout(3.0)
        chunk = b""
        try:
            chunk = conn.recv(512)
        except (socket.timeout, OSError):
            pass
        server.log.record(
            "tcp",
            self.client_address[0],
            {
                "port": server.server_address[1],
                "bytes": len(chunk),
                "preview": chunk[:64].hex() or None,
            },
        )
        try:
            conn.close()
        except OSError:
            pass


class SinkTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, log: EventLog, proto: str = "tcp", tls_ctx=None) -> None:
        super().__init__(addr, handler)
        self.log = log
        self.proto = proto
        if tls_ctx is not None:
            self.socket = tls_ctx.wrap_socket(self.socket, server_side=True)


# ------------------------------------------------------------------ TLS helpers


def make_self_signed_cert(dest_dir: str) -> Optional[str]:
    """Return path to a PEM file with cert+key, or None if we can't mint one."""
    pem_path = os.path.join(dest_dir, "sinkhole.pem")
    # Prefer the cryptography lib if present.
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime as _dt

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sinkhole.local")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime.utcnow() - _dt.timedelta(days=1))
            .not_valid_after(_dt.datetime.utcnow() + _dt.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("*")]), critical=False)
            .sign(key, hashes.SHA256())
        )
        with open(pem_path, "wb") as fh:
            fh.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        return pem_path
    except Exception:
        pass
    # Fall back to the openssl CLI.
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", pem_path, "-out", pem_path, "-days", "3650",
                "-subj", "/CN=sinkhole.local",
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        return pem_path
    except Exception:
        return None


# ---------------------------------------------------------------- orchestration


class Sinkhole:
    """Owns all listeners so tests can start/stop deterministically."""

    def __init__(
        self,
        answer_ip: str = DEFAULT_ANSWER_IP,
        bind_ip: str = "0.0.0.0",
        dns_port: int = 53,
        http_port: int = 80,
        https_port: int = 443,
        tcp_ports: Optional[list[int]] = None,
        log: Optional[EventLog] = None,
        enable_https: bool = True,
    ) -> None:
        self.answer_ip = answer_ip
        self.bind_ip = bind_ip
        self.dns_port = dns_port
        self.http_port = http_port
        self.https_port = https_port
        self.tcp_ports = DEFAULT_TCP_PORTS if tcp_ports is None else tcp_ports
        self.log = log or EventLog(None)
        self.enable_https = enable_https
        self._servers: list = []
        self._threads: list[threading.Thread] = []
        self._tmpdir: Optional[tempfile.TemporaryDirectory] = None
        self.started: list[str] = []

    def _serve(self, server) -> None:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._servers.append(server)
        self._threads.append(thread)

    def start(self) -> "Sinkhole":
        if self.dns_port is not None:
            try:
                self._serve(DnsServer((self.bind_ip, self.dns_port), self.answer_ip, self.log))
                self.started.append(f"dns/{self.dns_port}")
            except OSError as exc:
                print(f"[sinkhole] DNS :{self.dns_port} failed: {exc}", file=sys.stderr)
        if self.http_port is not None:
            try:
                self._serve(SinkTcpServer((self.bind_ip, self.http_port), _HttpTcpHandler, self.log, "http"))
                self.started.append(f"http/{self.http_port}")
            except OSError as exc:
                print(f"[sinkhole] HTTP :{self.http_port} failed: {exc}", file=sys.stderr)
        if self.https_port is not None and self.enable_https:
            self._tmpdir = tempfile.TemporaryDirectory()
            pem = make_self_signed_cert(self._tmpdir.name)
            if pem:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(pem)
                try:
                    self._serve(SinkTcpServer((self.bind_ip, self.https_port), _HttpTcpHandler, self.log, "https", tls_ctx=ctx))
                    self.started.append(f"https/{self.https_port}")
                except OSError as exc:
                    print(f"[sinkhole] HTTPS :{self.https_port} failed: {exc}", file=sys.stderr)
            else:
                print("[sinkhole] HTTPS disabled: no cryptography lib and no openssl CLI.", file=sys.stderr)
        for port in self.tcp_ports:
            try:
                self._serve(SinkTcpServer((self.bind_ip, port), _RawTcpHandler, self.log, "tcp"))
                self.started.append(f"tcp/{port}")
            except OSError as exc:
                print(f"[sinkhole] TCP :{port} failed: {exc}", file=sys.stderr)
        return self

    def actual_ports(self) -> dict[str, int]:
        """Map the first listener of each proto to its bound port (for ephemeral-port tests)."""
        ports: dict[str, int] = {}
        for server in self._servers:
            proto = getattr(server, "proto", "dns" if isinstance(server, DnsServer) else "tcp")
            ports.setdefault(proto, server.server_address[1])
        return ports

    def stop(self) -> None:
        for server in self._servers:
            try:
                server.shutdown()
                server.server_close()
            except Exception:  # noqa: BLE001
                pass
        if self._tmpdir:
            self._tmpdir.cleanup()
        self.log.close()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Arbiterion fake-internet sinkhole.")
    parser.add_argument("--answer-ip", default=DEFAULT_ANSWER_IP,
                        help="IP returned for every A query (host-only adapter IP).")
    parser.add_argument("--bind-ip", default="0.0.0.0", help="Interface to bind listeners to.")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--https-port", type=int, default=443)
    parser.add_argument("--tcp-ports", default=",".join(str(p) for p in DEFAULT_TCP_PORTS),
                        help="Comma-separated extra TCP ports to accept-and-log.")
    parser.add_argument("--no-https", action="store_true", help="Skip the HTTPS listener.")
    parser.add_argument("--log", default=None, help="JSONL connection log path.")
    parser.add_argument("--duration", type=int, default=0,
                        help="Auto-stop after N seconds (0 = run until Ctrl-C).")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    tcp_ports = [int(p) for p in args.tcp_ports.split(",") if p.strip()]
    log = EventLog(args.log, quiet=args.quiet)
    sink = Sinkhole(
        answer_ip=args.answer_ip,
        bind_ip=args.bind_ip,
        dns_port=args.dns_port,
        http_port=args.http_port,
        https_port=args.https_port,
        tcp_ports=tcp_ports,
        log=log,
        enable_https=not args.no_https,
    )
    sink.start()
    if not sink.started:
        print("[sinkhole] no listeners started; aborting.", file=sys.stderr)
        return 1
    print(f"[sinkhole] listening: {', '.join(sink.started)} | answer-ip={args.answer_ip}", flush=True)
    try:
        if args.duration:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        print("\n[sinkhole] shutting down.", flush=True)
    finally:
        sink.stop()
    print(f"[sinkhole] logged {len(log.records)} events.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
