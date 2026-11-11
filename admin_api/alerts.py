"""Independent BLOCK notifier. No imports or changes in the request-serving apps."""
import asyncio
import logging
import os
from pathlib import Path
import sqlite3

import aiohttp
from common.schema import DetectionLog, Verdict

LOG = logging.getLogger('blade.alerts')


def message(record: DetectionLog) -> str:
    return (f'[BLADE] {record.sub}가 {record.method} {record.path}에 접근 시도 — '
            f'정책 {record.policy_id}({record.label.value}) 위반: {record.reason}')


async def notify(record: DetectionLog, session: aiohttp.ClientSession,
                 slack: str = '', discord: str = '') -> None:
    if record.verdict != Verdict.BLOCK:
        return
    text = message(record)

    async def send(provider: str, url: str, payload: dict) -> None:
        if not url:
            return
        try:
            async with session.post(url, json=payload, allow_redirects=False) as response:
                if not 200 <= response.status < 300:
                    LOG.warning('%s delivery failed: status=%s request_id=%s', provider, response.status, record.request_id)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            # Never log webhook URLs or response bodies (they can contain secrets).
            LOG.warning('%s delivery failed: request_id=%s', provider, record.request_id)

    await asyncio.gather(send('slack', slack, {'text': text, 'mrkdwn': False}),
                         send('discord', discord, {'content': text[:2000], 'allowed_mentions': {'parse': []}}))


def read_batch(database: Path, after: int | None) -> tuple[int, list[tuple[int, DetectionLog]]]:
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True, timeout=2) as conn:
        conn.row_factory = sqlite3.Row
        latest = conn.execute('SELECT COALESCE(MAX(rowid),0) FROM detections').fetchone()[0]
        if after is None:
            return latest, []  # First start watches new events, not historical attacks.
        rows = conn.execute('SELECT rowid AS seq,* FROM detections WHERE rowid>? ORDER BY rowid LIMIT 100', (after,)).fetchall()
        return after, [(row['seq'], DetectionLog.model_validate({k: row[k] for k in row.keys() if k != 'seq'})) for row in rows]


def save_cursor(path: Path, cursor: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(str(cursor), encoding='utf-8')
    temporary.replace(path)


async def watch() -> None:
    database = Path(os.getenv('BLADE_ALERT_DB', '/data/blade.db'))
    checkpoint = Path(os.getenv('BLADE_ALERT_CURSOR', '/state/cursor'))
    cursor = int(checkpoint.read_text()) if checkpoint.exists() else None
    slack, discord = os.getenv('BLADE_SLACK_WEBHOOK', ''), os.getenv('BLADE_DISCORD_WEBHOOK', '')
    if not slack and not discord:
        LOG.info('No webhooks configured; watching without external delivery')
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
        while True:
            try:
                cursor, rows = await asyncio.to_thread(read_batch, database, cursor)
                for seq, record in rows:
                    await notify(record, session, slack, discord)
                    cursor = seq
                    await asyncio.to_thread(save_cursor, checkpoint, cursor)
                if not checkpoint.exists():
                    await asyncio.to_thread(save_cursor, checkpoint, cursor)
            except (sqlite3.Error, OSError, ValueError):
                LOG.warning('Detection watch failed; retrying')
            await asyncio.sleep(1)


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(watch())
