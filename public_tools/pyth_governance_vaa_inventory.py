#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

OUT = Path('evidence-vaa-inventory')
RAW = OUT / 'pages'
BASE = 'https://api.wormholescan.io'
EMITTER = '6oXTdojyfDS8m5VtTaYB9xRCxpKGSvKJFndLUPV3V3wT'
PAGE_SIZE = 50
EXPECTED_MAGIC = b'PTGM'


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            'accept': 'application/json',
            'user-agent': 'public-pyth-governance-inventory/1',
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def parse_vaa(encoded: str) -> dict[str, Any]:
    data = base64.b64decode(encoded)
    cursor = 0
    version = data[cursor]
    cursor += 1
    guardian_set_index = int.from_bytes(data[cursor:cursor + 4], 'big')
    cursor += 4
    signature_count = data[cursor]
    cursor += 1
    signatures = []
    for _ in range(signature_count):
        guardian_index = data[cursor]
        signature = data[cursor + 1:cursor + 66]
        cursor += 66
        signatures.append(
            {'guardian_index': guardian_index, 'signature': signature.hex()}
        )
    body_offset = cursor
    timestamp = int.from_bytes(data[cursor:cursor + 4], 'big')
    cursor += 4
    nonce = int.from_bytes(data[cursor:cursor + 4], 'big')
    cursor += 4
    emitter_chain = int.from_bytes(data[cursor:cursor + 2], 'big')
    cursor += 2
    emitter_address = data[cursor:cursor + 32].hex()
    cursor += 32
    sequence = int.from_bytes(data[cursor:cursor + 8], 'big')
    cursor += 8
    consistency_level = data[cursor]
    cursor += 1
    payload = data[cursor:]
    return {
        'version': version,
        'guardian_set_index': guardian_set_index,
        'signature_count': signature_count,
        'signatures': signatures,
        'body_offset': body_offset,
        'timestamp_unix': timestamp,
        'nonce': nonce,
        'emitter_chain': emitter_chain,
        'emitter_address': emitter_address,
        'sequence': sequence,
        'consistency_level': consistency_level,
        'payload': payload,
        'vaa_bytes': data,
    }


def decode_governance_payload(payload: bytes) -> dict[str, Any]:
    decoded: dict[str, Any] = {
        'payload_length': len(payload),
        'payload_hex': payload.hex(),
        'magic_ascii': payload[:4].decode(errors='replace') if len(payload) >= 4 else None,
        'valid_magic': len(payload) >= 4 and payload[:4] == EXPECTED_MAGIC,
        'module': payload[4] if len(payload) >= 5 else None,
        'action': payload[5] if len(payload) >= 6 else None,
        'target_chain_id': int.from_bytes(payload[6:8], 'big')
        if len(payload) >= 8
        else None,
    }
    if (
        decoded['valid_magic']
        and decoded['module'] == 2
        and decoded['action'] == 0
        and len(payload) >= 80
    ):
        decoded.update(
            {
                'executor_address': '0x' + payload[8:28].hex(),
                'call_address': '0x' + payload[28:48].hex(),
                'value': str(int.from_bytes(payload[48:80], 'big')),
                'calldata': '0x' + payload[80:].hex(),
                'calldata_selector': '0x' + payload[80:84].hex()
                if len(payload) >= 84
                else None,
                'calldata_length': max(0, len(payload) - 80),
            }
        )
    return decoded


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)
    all_items: list[dict[str, Any]] = []
    pages_fetched = 0
    for page in range(0, 100):
        url = (
            f'{BASE}/api/v1/vaas/1/{EMITTER}'
            f'?page={page}&pageSize={PAGE_SIZE}&sortOrder=DESC'
        )
        payload = fetch_json(url)
        (RAW / f'page-{page:02d}.json').write_text(
            json.dumps(payload, indent=2), encoding='utf-8'
        )
        items = payload.get('data')
        if not isinstance(items, list):
            raise RuntimeError(f'page {page} has no data list')
        pages_fetched += 1
        if not items:
            break
        all_items.extend(items)
        if len(items) < PAGE_SIZE:
            break

    decoded_rows: list[dict[str, Any]] = []
    raw_vaas_dir = OUT / 'signed-vaas'
    raw_vaas_dir.mkdir(exist_ok=True)
    failures: list[dict[str, Any]] = []
    for item in all_items:
        try:
            parsed = parse_vaa(item['vaa'])
            governance = decode_governance_payload(parsed['payload'])
            sequence = parsed['sequence']
            if sequence != int(item['sequence']):
                raise RuntimeError(
                    f'list/body sequence mismatch: {item["sequence"]} != {sequence}'
                )
            (raw_vaas_dir / f'{sequence}.vaa').write_bytes(parsed['vaa_bytes'])
            decoded_rows.append(
                {
                    'sequence': sequence,
                    'timestamp': item.get('timestamp'),
                    'tx_hash': item.get('txHash'),
                    'digest': item.get('digest'),
                    'guardian_set_index': parsed['guardian_set_index'],
                    'signature_count': parsed['signature_count'],
                    'timestamp_unix': parsed['timestamp_unix'],
                    'nonce': parsed['nonce'],
                    'emitter_chain': parsed['emitter_chain'],
                    'emitter_address': parsed['emitter_address'],
                    'consistency_level': parsed['consistency_level'],
                    **governance,
                }
            )
        except Exception as error:
            failures.append(
                {'sequence': item.get('sequence'), 'error': repr(error), 'item': item}
            )

    decoded_rows.sort(key=lambda row: int(row['sequence']))
    sequences = [int(row['sequence']) for row in decoded_rows]
    duplicate_sequences = sorted(
        sequence for sequence, count in Counter(sequences).items() if count != 1
    )
    expected_sequences = set(range(min(sequences), max(sequences) + 1)) if sequences else set()
    missing_sequences = sorted(expected_sequences - set(sequences))

    module_counts = Counter(str(row.get('module')) for row in decoded_rows)
    target_counts = Counter(str(row.get('target_chain_id')) for row in decoded_rows)
    module_action_counts = Counter(
        f'{row.get("module")}:{row.get("action")}' for row in decoded_rows
    )
    executor_rows = [
        row
        for row in decoded_rows
        if row.get('valid_magic') and row.get('module') == 2 and row.get('action') == 0
    ]
    global_rows = [row for row in decoded_rows if row.get('target_chain_id') == 0]
    global_executor_rows = [
        row for row in executor_rows if row.get('target_chain_id') == 0
    ]

    (OUT / 'decoded-vaas.json').write_text(
        json.dumps(decoded_rows, indent=2), encoding='utf-8'
    )
    (OUT / 'evm-executor-vaas.json').write_text(
        json.dumps(executor_rows, indent=2), encoding='utf-8'
    )
    (OUT / 'global-vaas.json').write_text(
        json.dumps(global_rows, indent=2), encoding='utf-8'
    )
    (OUT / 'global-evm-executor-vaas.json').write_text(
        json.dumps(global_executor_rows, indent=2), encoding='utf-8'
    )
    (OUT / 'decode-failures.json').write_text(
        json.dumps(failures, indent=2), encoding='utf-8'
    )

    columns = [
        'sequence',
        'timestamp',
        'tx_hash',
        'guardian_set_index',
        'signature_count',
        'module',
        'action',
        'target_chain_id',
        'payload_length',
        'executor_address',
        'call_address',
        'value',
        'calldata_selector',
        'calldata_length',
    ]
    with (OUT / 'decoded-vaas.csv').open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(decoded_rows)

    summary = {
        'schema': 'pyth-governance-vaa-inventory/v1',
        'generated_at_unix': int(time.time()),
        'pages_fetched': pages_fetched,
        'list_item_count': len(all_items),
        'decoded_count': len(decoded_rows),
        'decode_failure_count': len(failures),
        'minimum_sequence': min(sequences) if sequences else None,
        'maximum_sequence': max(sequences) if sequences else None,
        'missing_sequences': missing_sequences,
        'duplicate_sequences': duplicate_sequences,
        'module_counts': dict(sorted(module_counts.items())),
        'module_action_counts': dict(sorted(module_action_counts.items())),
        'target_counts': dict(sorted(target_counts.items(), key=lambda item: int(item[0]))),
        'evm_executor_count': len(executor_rows),
        'global_count': len(global_rows),
        'global_evm_executor_count': len(global_executor_rows),
        'global_evm_executor_sequences': [row['sequence'] for row in global_executor_rows],
        'global_evm_executor_addresses': sorted(
            {str(row.get('executor_address')) for row in global_executor_rows}
        ),
    }
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    text = '\n'.join(
        [
            f'PAGES_FETCHED={pages_fetched}',
            f'LIST_ITEM_COUNT={len(all_items)}',
            f'DECODED_COUNT={len(decoded_rows)}',
            f'DECODE_FAILURE_COUNT={len(failures)}',
            f'MIN_SEQUENCE={summary["minimum_sequence"]}',
            f'MAX_SEQUENCE={summary["maximum_sequence"]}',
            f'MISSING_SEQUENCE_COUNT={len(missing_sequences)}',
            f'DUPLICATE_SEQUENCE_COUNT={len(duplicate_sequences)}',
            f'EVM_EXECUTOR_COUNT={len(executor_rows)}',
            f'GLOBAL_COUNT={len(global_rows)}',
            f'GLOBAL_EVM_EXECUTOR_COUNT={len(global_executor_rows)}',
            'GLOBAL_EVM_EXECUTOR_SEQUENCES='
            + ','.join(str(x) for x in summary['global_evm_executor_sequences']),
        ]
    ) + '\n'
    (OUT / 'summary.txt').write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if not failures and not missing_sequences and not duplicate_sequences else 2


if __name__ == '__main__':
    raise SystemExit(main())
