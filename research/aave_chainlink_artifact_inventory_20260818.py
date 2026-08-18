#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import json
import zipfile

ROOT = Path('artifact')
OUTPUT = Path('research/results/aave_chainlink_artifact_inventory_20260818.json')
OUTPUT.parent.mkdir(parents=True, exist_ok=True)

# The downloaded artifact may be a directory or contain one nested ZIP.
for archive in list(ROOT.rglob('*.zip')):
    target = archive.with_suffix('')
    target.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(target)
    except zipfile.BadZipFile:
        pass

rows = []
for path in sorted(ROOT.rglob('*')):
    if not path.is_file():
        continue
    row = {
        'path': path.as_posix(),
        'size': path.stat().st_size,
        'suffix': path.suffix.lower(),
    }
    if path.suffix.lower() == '.json' and path.stat().st_size <= 120_000_000:
        try:
            data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
            row['json_type'] = type(data).__name__
            if isinstance(data, dict):
                row['keys'] = list(data.keys())[:80]
            elif isinstance(data, list):
                row['length'] = len(data)
                if data and isinstance(data[0], dict):
                    row['first_keys'] = list(data[0].keys())[:80]
        except Exception as exc:
            row['json_error'] = repr(exc)
    rows.append(row)

OUTPUT.write_text(json.dumps({'files': rows}, indent=2) + '\n', encoding='utf-8')
print(OUTPUT)
