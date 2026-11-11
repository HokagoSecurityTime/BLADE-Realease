"""Optional, rate-limited NVD 2.0 collector. Runs only by explicit CLI invocation."""
import argparse
import asyncio
import json
import os
from pathlib import Path

import aiohttp

from common.features import enabled

KEYWORDS = ('IDOR', 'object level authorization', 'insecure direct object')


def parse_response(payload: dict) -> list[dict]:
    rows = []
    for entry in payload.get('vulnerabilities', []):
        cve = entry['cve']
        summary = next((d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'), '')
        if cve.get('vulnStatus') == 'Rejected' or not summary:
            continue
        rows.append(dict(cve_id=cve['id'], summary=summary,
            cwe=sorted({d['value'] for w in cve.get('weaknesses', []) for d in w.get('description', []) if d['lang'] == 'en'}),
            published=cve.get('published', ''), refs=[r['url'] for r in cve.get('references', [])]))
    return rows


async def collect(output: Path, max_pages: int = 1) -> int:
    if not enabled('BLADE_CVE_ENABLED'):
        return 0
    key = os.getenv('NVD_API_KEY', '')
    delay = 1 if key else 7  # NVD: 50/30 s with key; 5/30 s without.
    rows: dict[str, dict] = {}
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60), headers={'apiKey': key} if key else {}) as session:
        first = True
        for keyword in KEYWORDS:
            for page in range(max_pages):
                if not first:
                    await asyncio.sleep(delay)
                first = False
                async with session.get('https://services.nvd.nist.gov/rest/json/cves/2.0',
                        params={'keywordSearch': keyword, 'resultsPerPage': 100, 'startIndex': page * 100}) as response:
                    response.raise_for_status()
                    payload = await response.json()
                for item in parse_response(payload):
                    rows[item['cve_id']] = item
                if (page + 1) * 100 >= payload.get('totalResults', 0):
                    break
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows.values()), encoding='utf-8')
    if enabled('BLADE_RAG_ENABLED'):
        from pipeline.rag.index import Index
        from pipeline.rag.corpus import load_cves
        Index().replace('cve', load_cves(output))
    return len(rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('corpus/cve.jsonl'))
    parser.add_argument('--max-pages', type=int, default=1)
    args = parser.parse_args()
    if args.max_pages < 1:
        parser.error('--max-pages must be positive')
    print(f'Collected {asyncio.run(collect(args.output, args.max_pages))} CVEs')
