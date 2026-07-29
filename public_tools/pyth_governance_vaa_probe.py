#!/usr/bin/env python3
from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any

OUT = Path('evidence-vaa-probe')
BASE = 'https://api.wormholescan.io'
EMITTER_BASE58 = '6oXTdojyfDS8m5VtTaYB9xRCxpKGSvKJFndLUPV3V3wT'
EMITTER_HEX = '5635979a221c34931e32620b9293a463065555ea71fe97cd6237ade875b12e9e'


def get_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            'accept': 'application/json',
            'user-agent': 'public-governance-vaa-inventory/1',
        },
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    candidates = [
        f'{BASE}/api/v1/vaas/1/{EMITTER_BASE58}',
        f'{BASE}/api/v1/vaas/1/{EMITTER_BASE58}?pageSize=5&sortOrder=DESC',
        f'{BASE}/api/v1/vaas/1/{EMITTER_HEX}?pageSize=5&sortOrder=DESC',
        f'{BASE}/api/v1/vaas/1/{EMITTER_BASE58}?page=1&pageSize=5&sortOrder=DESC',
        f'{BASE}/api/v1/vaas/1/{EMITTER_BASE58}?page=2&pageSize=5&sortOrder=DESC',
        f'{BASE}/api/v1/vaas/1/{EMITTER_BASE58}?page=10&pageSize=50&sortOrder=DESC',
        f'{BASE}/api/v1/vaas/1/{EMITTER_BASE58}?page=14&pageSize=50&sortOrder=DESC',
    ]
    responses: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for index, url in enumerate(candidates):
        try:
            payload = get_json(url)
            responses.append({'url': url, 'payload': payload})
            (OUT / f'response-{index}.json').write_text(
                json.dumps(payload, indent=2), encoding='utf-8'
            )
        except Exception as error:
            failures.append({'url': url, 'error': repr(error)})

    summary = {
        'successful_count': len(responses),
        'failures': failures,
        'response_shapes': [
            {
                'url': item['url'],
                'top_level_keys': sorted(item['payload'].keys()),
                'pagination': item['payload'].get('pagination'),
                'data_type': type(item['payload'].get('data')).__name__,
                'data_length': len(item['payload'].get('data', []))
                if isinstance(item['payload'].get('data'), list)
                else None,
                'first_sequence': item['payload']['data'][0].get('sequence')
                if isinstance(item['payload'].get('data'), list)
                and item['payload'].get('data')
                else None,
                'last_sequence': item['payload']['data'][-1].get('sequence')
                if isinstance(item['payload'].get('data'), list)
                and item['payload'].get('data')
                else None,
                'first_item_keys': sorted(item['payload']['data'][0].keys())
                if isinstance(item['payload'].get('data'), list)
                and item['payload']['data']
                and isinstance(item['payload']['data'][0], dict)
                else None,
            }
            for item in responses
        ],
    }
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))
    return 0 if responses else 2


if __name__ == '__main__':
    raise SystemExit(main())
