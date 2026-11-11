import asyncio
from collections.abc import Callable
import logging
from time import monotonic

import aiohttp

from common.features import enabled
from common.schema import DetectionLog


def message(record: DetectionLog) -> str:
    text = (f'[BLADE {record.mode}] {record.sub} → {record.method} {record.path} · '
            f'정책 {record.policy_id}({record.label.value}) · {record.reason}')
    return text + ('\n' + record.explanation if record.explanation else '')


class AlertWorker:
    def __init__(self, clock: Callable[[], float] = monotonic) -> None:
        self.clock = clock
        self.seen: dict[tuple[str, str], float] = {}

    async def notify(self, record: DetectionLog, session: aiohttp.ClientSession,
                     settings: dict[str, str]) -> bool:
        if not enabled('BLADE_ALERTS_ENABLED'):
            return False
        blocked = record.verdict == 'BLOCK' and record.mode == 'enforce'
        if not (blocked or record.would_block) or (settings['min_severity'] == 'block' and not blocked):
            return False
        if not settings['slack_webhook'] and not settings['discord_webhook']:
            return False
        now = self.clock()
        self.seen = {key: until for key, until in self.seen.items() if until > now}
        key = (record.sub, record.policy_id)
        if key in self.seen:
            return False
        self.seen[key] = now + 60
        text = message(record)

        async def send(provider: str, url: str, payload: dict) -> bool:
            if not url:
                return False
            for attempt in range(2):
                try:
                    async with session.post(url, json=payload, allow_redirects=False) as response:
                        if 200 <= response.status < 300:
                            return True
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
                    pass
                logging.warning('Phase 2 %s alert failed; attempt=%s request_id=%s', provider, attempt+1, record.request_id)
                if attempt == 0:
                    await asyncio.sleep(.1)
            return False

        delivered = await asyncio.gather(
            send('slack', settings['slack_webhook'], {'text': text, 'mrkdwn': False}),
            send('discord', settings['discord_webhook'], {'content': text[:2000], 'allowed_mentions': {'parse': []}}))
        return any(delivered)
