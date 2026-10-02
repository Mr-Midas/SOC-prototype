#!/usr/bin/env python3
"""Chain-of-custody manifest for Arbiterion detonations.

Records exactly what was detonated, when, and with which parameters, so a run
is reproducible and auditable. The host orchestrator (analysis-vm.ps1) calls
this before a detonation to stamp the results directory; it can also be used
standalone to hash a sample.

Subcommands:
  hash <file>                      Print the SHA-256 of a file.
  record --sample <f> --out <dir> [--vm NAME] [--observe N] [--snapshot S]
                                   [--extra k=v ...]
                                   Write <dir>/run-manifest.json describing the run.

The manifest never executes or opens the sample as code; it only hashes bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def sha256_file(path: str | os.PathLike, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha1_file(path: str | os.PathLike, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha1()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(
    sample: str | os.PathLike,
    vm: str = "",
    observe_seconds: Optional[int] = None,
    snapshot: str = "",
    extra: Optional[dict] = None,
) -> dict:
    sample_path = Path(sample)
    if not sample_path.is_file():
        raise FileNotFoundError(f"sample not found: {sample_path}")
    stat = sample_path.stat()
    manifest = {
        "schema": "arbiterion.detonation-manifest/v1",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "sample": {
            "filename": sample_path.name,
            "size_bytes": stat.st_size,
            "sha256": sha256_file(sample_path),
            "sha1": sha1_file(sample_path),
            "suffix": sample_path.suffix.lower(),
        },
        "vm": vm,
        "observe_seconds": observe_seconds,
        "snapshot": snapshot,
        "extra": extra or {},
    }
    return manifest


def _parse_extra(pairs: list[str]) -> dict:
    out: dict[str, str] = {}
    for item in pairs or []:
        if "=" not in item:
            raise ValueError(f"--extra expects key=value, got {item!r}")
        key, value = item.split("=", 1)
        out[key.strip()] = value.strip()
    return out


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Arbiterion detonation manifest.")
    sub = parser.add_subparsers(dest="command", required=True)

    hash_cmd = sub.add_parser("hash", help="Print SHA-256 of a file.")
    hash_cmd.add_argument("file")

    record = sub.add_parser("record", help="Write a run manifest into a results dir.")
    record.add_argument("--sample", required=True)
    record.add_argument("--out", required=True, help="Results directory (created if missing).")
    record.add_argument("--vm", default="")
    record.add_argument("--observe", type=int, default=None)
    record.add_argument("--snapshot", default="")
    record.add_argument("--extra", nargs="*", default=[], help="Extra key=value pairs.")

    args = parser.parse_args(argv)

    if args.command == "hash":
        print(sha256_file(args.file))
        return 0

    if args.command == "record":
        manifest = build_manifest(
            args.sample,
            vm=args.vm,
            observe_seconds=args.observe,
            snapshot=args.snapshot,
            extra=_parse_extra(args.extra),
        )
        out_dir = Path(args.out)
        out_dir.mkdir(parents=True, exist_ok=True)
        dest = out_dir / "run-manifest.json"
        dest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"Wrote {dest}")
        print(f"  sample : {manifest['sample']['filename']}")
        print(f"  sha256 : {manifest['sample']['sha256']}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
