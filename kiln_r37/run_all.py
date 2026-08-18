#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path("r37b_persisted/LATEST")
RESULTS = Path("r37_results")
SCRIPT = Path("kiln_r37/fee_invariant_census.py")
PUBLIC_KEY = Path("kiln_r37/delivery_public.pem")
CASES = (
    ("ethereum", 0, 4), ("ethereum", 1, 4),
    ("ethereum", 2, 4), ("ethereum", 3, 4),
    ("arbitrum", 0, 2), ("arbitrum", 1, 2),
    ("base", 0, 1), ("bnb", 0, 1),
    ("polygon", 0, 1), ("optimism", 0, 1),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_sums(directory: Path) -> None:
    files = sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt")
    (directory / "SHA256SUMS.txt").write_text(
        "".join(f"{sha256(p)}  {p.relative_to(directory).as_posix()}\n" for p in files)
    )


def verify_sums(directory: Path) -> None:
    for line in (directory / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert sha256(directory / name) == digest, name


def fail_closed_gate(network: str, shard: int, count: int, code: int) -> dict:
    return {
        "schema": "kiln-r37b-fallback-v1",
        "decision": "INCONCLUSIVE_EXECUTION_FAILURE",
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "network": network,
        "shard_index": shard,
        "shard_count": count,
        "selected_count": 0,
        "inspected_count": 0,
        "error_count": 1,
        "candidate_count": 0,
        "runner_exit_code": code,
        "public_chain_state_changes": 0,
        "transactions_signed": 0,
        "transactions_sent": 0,
    }


def run_case(network: str, shard: int, count: int) -> tuple[dict, dict]:
    key = f"{network}_{shard}"
    shutil.rmtree(RESULTS, ignore_errors=True)
    env = os.environ.copy()
    env.update(TARGET_NETWORK=network, SHARD_INDEX=str(shard), SHARD_COUNT=str(count))
    proc = subprocess.run(
        ["python3", str(SCRIPT)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=1800,
        check=False,
    )
    log = proc.stdout
    gate_path = RESULTS / "PUBLIC_GATE.json"
    if gate_path.exists():
        gate = json.loads(gate_path.read_text())
    else:
        RESULTS.mkdir(exist_ok=True)
        gate = fail_closed_gate(network, shard, count, proc.returncode)
    gate["runner_exit_code"] = proc.returncode
    if proc.returncode != 0:
        gate.update(
            decision="INCONCLUSIVE_EXECUTION_FAILURE",
            submit_ready=False,
            validated_critical=0,
            validated_high=0,
        )
    gate_path.write_text(json.dumps(gate, indent=2, sort_keys=True))
    write_sums(RESULTS)
    verify_sums(RESULTS)

    public_dir = ROOT / "public_gates" / key
    public_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(gate_path, public_dir / "PUBLIC_GATE.json")
    shutil.copy2(RESULTS / "SHA256SUMS.txt", public_dir / "PRIVATE_SHA256SUMS.txt")

    with tempfile.TemporaryDirectory(prefix=f"r37b_{key}_") as tmp_name:
        tmp = Path(tmp_name)
        (tmp / "runner.log").write_text(log)
        (tmp / "runner.exit").write_text(f"{proc.returncode}\n")
        tar_path = tmp / "evidence.tar.gz"
        with tarfile.open(tar_path, "w:gz") as archive:
            archive.add(RESULTS, arcname="r37_results")
            archive.add(SCRIPT, arcname=SCRIPT.as_posix())
            archive.add(tmp / "runner.log", arcname="runner.log")
            archive.add(tmp / "runner.exit", arcname="runner.exit")
        aes_path = tmp / "aes.key"
        aes_path.write_bytes(os.urandom(32))
        payload = tmp / "payload.aes256"
        wrapped = tmp / "key.rsa3072"
        subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-iter", "250000",
             "-in", str(tar_path), "-out", str(payload), "-pass", f"file:{aes_path}"],
            check=True,
        )
        subprocess.run(
            ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", str(PUBLIC_KEY),
             "-in", str(aes_path), "-out", str(wrapped),
             "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256"],
            check=True,
        )
        encrypted_dir = ROOT / "encrypted_b64" / key
        encrypted_dir.mkdir(parents=True, exist_ok=True)
        encrypted_rows = []
        for source in (payload, wrapped):
            raw = source.read_bytes()
            encoded = base64.b64encode(raw)
            assert base64.b64decode(encoded, validate=True) == raw
            target = encrypted_dir / f"{source.name}.b64"
            target.write_bytes(encoded + b"\n")
            encrypted_rows.append(
                {"file": source.name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                 "roundtrip_ok": True, "b64_file": target.name}
            )
        roundtrip = {"key": key, "files": encrypted_rows, "all_roundtrip_ok": True}
        (encrypted_dir / "ROUNDTRIP.json").write_text(json.dumps(roundtrip, indent=2, sort_keys=True))
    return gate, roundtrip


def main() -> int:
    if ROOT.exists():
        shutil.rmtree(ROOT)
    (ROOT / "public_gates").mkdir(parents=True)
    (ROOT / "encrypted_b64").mkdir(parents=True)

    gates: list[dict] = []
    roundtrips: list[dict] = []
    for case in CASES:
        gate, roundtrip = run_case(*case)
        gates.append(gate)
        roundtrips.append(roundtrip)

    seen = {(str(g.get("network")), int(g.get("shard_index", -1)), int(g.get("shard_count", -1))) for g in gates}
    selected = sum(int(g.get("selected_count", 0) or 0) for g in gates)
    inspected = sum(int(g.get("inspected_count", 0) or 0) for g in gates)
    errors = sum(int(g.get("error_count", 0) or 0) for g in gates)
    candidates = sum(int(g.get("candidate_count", 0) or 0) for g in gates)
    exit_errors = sum(int(g.get("runner_exit_code", 1) or 0) != 0 for g in gates)
    complete = (
        seen == set(CASES) and len(gates) == 10 and selected == 101 and inspected == 101
        and errors == 0 and exit_errors == 0 and len(roundtrips) == 10
        and all(r["all_roundtrip_ok"] for r in roundtrips)
    )
    decision = (
        "HOLD_PRIVATE_FEE_SIGNAL_REVIEW" if complete and candidates
        else "KILL_NO_LIVE_FEE_INVARIANT_SIGNAL" if complete
        else "INCONCLUSIVE_COVERAGE_OR_INTEGRITY_FAILURE"
    )
    aggregate = {
        "schema": "kiln-r37b-persisted-aggregate-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "decision": decision,
        "submit_ready": False,
        "validated_critical": 0,
        "validated_high": 0,
        "coverage_complete": complete,
        "expected_shards": 10,
        "public_gate_count": len(gates),
        "encrypted_export_count": len(roundtrips),
        "selected_total": selected,
        "inspected_total": inspected,
        "error_total": errors,
        "candidate_total": candidates,
        "runner_exit_error_count": exit_errors,
        "seen_shards": [list(x) for x in sorted(seen)],
        "rows": gates,
        "roundtrips": roundtrips,
        "safety": {
            "public_chain_state_changes": 0,
            "transactions_signed": 0,
            "transactions_sent": 0,
            "private_keys_included": False,
        },
    }
    (ROOT / "AGGREGATE_PUBLIC.json").write_text(json.dumps(aggregate, indent=2, sort_keys=True))
    write_sums(ROOT)
    verify_sums(ROOT)
    assert aggregate["submit_ready"] is False
    assert aggregate["validated_critical"] == aggregate["validated_high"] == 0
    assert not any(b"BEGIN PRIVATE KEY" in p.read_bytes() for p in ROOT.rglob("*") if p.is_file())
    print(json.dumps(aggregate, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
