"""Policy snapshots/notifications; all proxy activity runs in a background task."""
import asyncio
from collections.abc import Awaitable, Callable
import json
import logging
import os

from common.features import enabled
from common.schema import Policy

CHANNEL = 'blade:policy'
KEY = 'blade:policies'


def redis_url() -> str:
    return os.getenv('BLADE_REDIS_URL', '') if enabled('BLADE_REDIS_ENABLED') else ''


def publish(policies: list[Policy]) -> None:
    url = redis_url()
    if not url:
        return
    try:
        import redis
        from redis.backoff import NoBackoff
        from redis.retry import Retry
        payload = json.dumps([p.model_dump(mode='json') for p in policies])
        with redis.Redis.from_url(url, socket_connect_timeout=.25, socket_timeout=.25,
                                  retry=Retry(NoBackoff(), 0)) as client:
            with client.pipeline(transaction=True) as transaction:
                transaction.set(KEY, payload, ex=60)
                transaction.publish(CHANNEL, payload)
                transaction.execute()
    except Exception:
        # Policy commits remain valid even when the notification infrastructure fails.
        logging.warning('Redis policy publication failed; polling reconciliation will recover')


class PolicySubscriber:
    def __init__(self) -> None:
        self.url = redis_url()
        self.connected = False

    async def run(self, apply: Callable[[list[Policy]], Awaitable[None]],
                  refresh: Callable[[], Awaitable[None]]) -> None:
        if not self.url:
            return
        while True:
            try:
                import redis.asyncio as redis
                from redis.backoff import NoBackoff
                from redis.asyncio.retry import Retry
                async with redis.Redis.from_url(self.url, socket_connect_timeout=.25, socket_timeout=2,
                                                retry=Retry(NoBackoff(), 0)) as client:
                    async with client.pubsub() as subscription:
                        await subscription.subscribe(CHANNEL)
                        # Admin is authoritative; repair snapshots after reconnection.
                        # Do not replace an existing snapshot with a potentially stale
                        # Redis value left behind by an earlier publication failure.
                        await refresh()
                        self.connected = True
                        while True:
                            message = await subscription.get_message(ignore_subscribe_messages=True, timeout=1)
                            if message:
                                cached = await client.get(KEY)
                                await apply([Policy.model_validate(row) for row in json.loads(cached or message['data'])])
                            await asyncio.sleep(.01)
            except asyncio.CancelledError:
                raise
            except Exception:
                logging.warning('Redis policy subscription unavailable; using admin polling')
                await asyncio.sleep(.5)
            finally:
                self.connected = False
