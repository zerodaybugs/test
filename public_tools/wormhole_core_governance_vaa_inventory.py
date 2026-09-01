#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

OUT = Path('evidence-wormhole-core-governance')
PAGES = OUT / 'pages'
SIGNED = OUT / 'signed-vaas'
BASE = 'https://api.wormholescan.io'
# Wormhole Core governance emitter: bytes32(4), encoded as a Solana public key.
EMITTER = '11111111111111111111111111111115'
PAGE_SIZE = 50
CORE_MODULE = bytes(28) + b'Core'


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            'accept': 'application/json',
            'user-agent': 'wormhole-core-governance-inventory/1',
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
    cursor += signature_count * 66
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
        'raw': data,
        'version': version,
        'guardian_set_index': guardian_set_index,
        'signature_count': signature_count,
        'timestamp_unix': timestamp,
        'nonce': nonce,
        'emitter_chain': emitter_chain,
        'emitter_address': emitter_address,
        'sequence': sequence,
        'consistency_level': consistency_level,
        'payload': payload,
    }


def decode_core_payload(payload: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {
        'payload_length': len(payload),
        'payload_hex': payload.hex(),
        'module_hex': payload[:32].hex() if len(payload) >= 32 else None,
        'module_ascii': payload[:32].lstrip(b'\x00').decode(errors='replace')
        if len(payload) >= 32
        else None,
        'is_core_module': len(payload) >= 32 and payload[:32] == CORE_MODULE,
        'action': payload[32] if len(payload) >= 33 else None,
        'target_chain_id': int.from_bytes(payload[33:35], 'big')
        if len(payload) >= 35
        else None,
    }
    if result['is_core_module'] and result['action'] == 2 and len(payload) >= 40:
        new_index = int.from_bytes(payload[35:39], 'big')
        guardian_count = payload[39]
        expected_length = 40 + guardian_count * 20
        guardians = [
            '0x' + payload[40 + i * 20:40 + (i + 1) * 20].hex()
            for i in range(guardian_count)
            if 40 + (i + 1) * 20 <= len(payload)
        ]
        result.update(
            {
                'guardian_set_update': True,
                'new_guardian_set_index': new_index,
                'new_guardian_count': guardian_count,
                'new_guardians': guardians,
                'expected_payload_length': expected_length,
                'exact_payload_length': len(payload) == expected_length,
            }
        )
    else:
        result['guardian_set_update'] = False
    return result


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    PAGES.mkdir(exist_ok=True)
    SIGNED.mkdir(exist_ok=True)
    all_items: list[dict[str, Any]] = []
    pages_fetched = 0
    for page in range(0, 100):
        url = (
            f'{BASE}/api/v1/vaas/1/{EMITTER}'
            f'?page={page}&pageSize={PAGE_SIZE}&sortOrder=DESC'
        )
        payload = fetch_json(url)
        (PAGES / f'page-{page:02d}.json').write_text(
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

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for item in all_items:
        try:
            parsed = parse_vaa(item['vaa'])
            decoded = decode_core_payload(parsed['payload'])
            if parsed['sequence'] != int(item['sequence']):
                raise RuntimeError('list/body sequence mismatch')
            sequence = parsed['sequence']
            (SIGNED / f'{sequence}.vaa').write_bytes(parsed['raw'])
            rows.append(
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
                    **decoded,
                }
            )
        except Exception as error:
            failures.append(
                {'sequence': item.get('sequence'), 'error': repr(error)}
            )

    rows.sort(key=lambda row: int(row['sequence']))
    sequences = [int(row['sequence']) for row in rows]
    duplicates = sorted(
        sequence for sequence, count in Counter(sequences).items() if count != 1
    )
    expected = set(range(min(sequences), max(sequences) + 1)) if sequences else set()
    missing = sorted(expected - set(sequences))
    guardian_updates = [row for row in rows if row['guardian_set_update']]
    non_global_guardian_updates = [
        row for row in guardian_updates if row['target_chain_id'] != 0
    ]

    (OUT / 'decoded-vaas.json').write_text(
        json.dumps(rows, indent=2), encoding='utf-8'
    )
    (OUT / 'guardian-set-updates.json').write_text(
        json.dumps(guardian_updates, indent=2), encoding='utf-8'
    )
    (OUT / 'non-global-guardian-set-updates.json').write_text(
        json.dumps(non_global_guardian_updates, indent=2), encoding='utf-8'
    )
    (OUT / 'decode-failures.json').write_text(
        json.dumps(failures, indent=2), encoding='utf-8'
    )

    summary = {
        'schema': 'wormhole-core-governance-inventory/v1',
        'generated_at_unix': int(time.time()),
        'pages_fetched': pages_fetched,
        'list_item_count': len(all_items),
        'decoded_count': len(rows),
        'decode_failure_count': len(failures),
        'minimum_sequence': min(sequences) if sequences else None,
        'maximum_sequence': max(sequences) if sequences else None,
        'missing_sequences': missing,
        'duplicate_sequences': duplicates,
        'core_module_count': sum(1 for row in rows if row['is_core_module']),
        'guardian_set_update_count': len(guardian_updates),
        'guardian_set_update_sequences': [row['sequence'] for row in guardian_updates],
        'guardian_set_update_target_chains': [
            row['target_chain_id'] for row in guardian_updates
        ],
        'non_global_guardian_set_update_count': len(non_global_guardian_updates),
        'non_global_guardian_set_updates': non_global_guardian_updates,
    }
    (OUT / 'summary.json').write_text(
        json.dumps(summary, indent=2), encoding='utf-8'
    )
    text = '\n'.join(
        [
            f'PAGES_FETCHED={pages_fetched}',
            f'LIST_ITEM_COUNT={len(all_items)}',
            f'DECODED_COUNT={len(rows)}',
            f'DECODE_FAILURE_COUNT={len(failures)}',
            f'MIN_SEQUENCE={summary["minimum_sequence"]}',
            f'MAX_SEQUENCE={summary["maximum_sequence"]}',
            f'MISSING_SEQUENCE_COUNT={len(missing)}',
            f'DUPLICATE_SEQUENCE_COUNT={len(duplicates)}',
            f'CORE_MODULE_COUNT={summary["core_module_count"]}',
            f'GUARDIAN_SET_UPDATE_COUNT={len(guardian_updates)}',
            'GUARDIAN_SET_UPDATE_SEQUENCES='
            + ','.join(str(row['sequence']) for row in guardian_updates),
            'GUARDIAN_SET_UPDATE_TARGET_CHAINS='
            + ','.join(str(row['target_chain_id']) for row in guardian_updates),
            f'NON_GLOBAL_GUARDIAN_SET_UPDATE_COUNT={len(non_global_guardian_updates)}',
        ]
    ) + '\n'
    (OUT / 'summary.txt').write_text(text, encoding='utf-8')
    print(text, end='')
    return 0 if not failures and not missing and not duplicates else 2


if __name__ == '__main__':
    raise SystemExit(main())
