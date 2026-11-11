"""Background-only detection delivery. Redis entries are removed after DB commit."""
import asyncio
import hashlib
import logging
import os
from typing import TYPE_CHECKING, Any
from pydantic import TypeAdapter

from common.features import enabled
from common.redis_policy import redis_url
from common.schema import DetectionLog

if TYPE_CHECKING:
    from admin_api.store import Store

RECORDS = TypeAdapter(list[DetectionLog])


def decode_records(fields: dict[str, str]) -> list[DetectionLog]:
    """Accept both legacy single-record entries and batched transport entries."""
    if 'records' in fields:
        return RECORDS.validate_json(fields['records'])
    return [DetectionLog.model_validate_json(fields['record'])]


def stream_name() -> str:
    namespace = os.getenv('BLADE_DETECTION_STREAM_NAMESPACE') or hashlib.sha256(
        os.getenv('BLADE_DB_DSN', 'sqlite:///demo.db').encode()).hexdigest()[:16]
    return 'blade:detections:' + namespace


def client() -> Any:
    if not redis_url() or not enabled('BLADE_DETECTION_STREAM_ENABLED'):
        return None
    from redis.asyncio import Redis
    from redis.asyncio.retry import Retry
    from redis.backoff import NoBackoff
    url = os.getenv('BLADE_DETECTION_REDIS_URL') or redis_url()
    return Redis.from_url(url, decode_responses=True, socket_connect_timeout=.25,
                          socket_timeout=2, retry=Retry(NoBackoff(), 0))


async def consume(store: 'Store', stop: asyncio.Event) -> None:
    remote = client()
    if remote is None:
        return
    try:
        destination = stream_name()
        while True:
            try:
                batches = await remote.xread({destination: '0-0'}, count=16, block=100)
                if not batches:
                    if stop.is_set(): return
                    continue
                entries = batches[0][1]
                records = [record for _, fields in entries for record in decode_records(fields)]
                await asyncio.to_thread(store.append_detections, records, deduplicate=True)
                # Replay after a crash between commit and XDEL is idempotent.
                await remote.xdel(destination, *(identifier for identifier, _ in entries))
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.warning('Detection stream delivery unavailable; unacknowledged entries retained')
                if stop.is_set(): return
                await asyncio.sleep(.5)
    finally:
        await remote.aclose()
