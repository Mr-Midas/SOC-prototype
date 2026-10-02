"""Tests for the detonation chain-of-custody manifest."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import lab_manifest  # noqa: E402


def test_sha256_file_matches_hashlib(tmp_path):
    sample = tmp_path / "loader.bin"
    data = b"MZ\x90\x00" + b"malicious-ish bytes" * 100
    sample.write_bytes(data)
    assert lab_manifest.sha256_file(sample) == hashlib.sha256(data).hexdigest()


def test_build_manifest_fields(tmp_path):
    sample = tmp_path / "dropper.exe"
    sample.write_bytes(b"payload")
    m = lab_manifest.build_manifest(
        sample, vm="Arbiterion-Analysis", observe_seconds=90, snapshot="Before-Detonation-x",
        extra={"analyst": "me"},
    )
    assert m["sample"]["filename"] == "dropper.exe"
    assert m["sample"]["suffix"] == ".exe"
    assert m["sample"]["size_bytes"] == len(b"payload")
    assert m["sample"]["sha256"] == hashlib.sha256(b"payload").hexdigest()
    assert m["vm"] == "Arbiterion-Analysis"
    assert m["observe_seconds"] == 90
    assert m["extra"]["analyst"] == "me"
    assert m["schema"].startswith("arbiterion.detonation-manifest")


def test_build_manifest_missing_sample(tmp_path):
    with pytest.raises(FileNotFoundError):
        lab_manifest.build_manifest(tmp_path / "nope.exe")


def test_record_cli_writes_manifest(tmp_path):
    sample = tmp_path / "sample.js"
    sample.write_bytes(b"var x = 1;")
    out = tmp_path / "results"
    rc = lab_manifest.main([
        "record", "--sample", str(sample), "--out", str(out),
        "--vm", "VM1", "--observe", "60", "--extra", "ticket=ABC-1",
    ])
    assert rc == 0
    manifest = json.loads((out / "run-manifest.json").read_text())
    assert manifest["sample"]["suffix"] == ".js"
    assert manifest["vm"] == "VM1"
    assert manifest["observe_seconds"] == 60
    assert manifest["extra"]["ticket"] == "ABC-1"


def test_hash_cli(tmp_path, capsys):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"abc")
    rc = lab_manifest.main(["hash", str(sample)])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert out == hashlib.sha256(b"abc").hexdigest()


def test_parse_extra_rejects_bad_pair():
    with pytest.raises(ValueError):
        lab_manifest._parse_extra(["noequalssign"])
