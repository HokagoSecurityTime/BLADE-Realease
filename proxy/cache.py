"""Replaceable in-memory ownership cache; None is a cached missing row."""
import os
import time
import hashlib
import json
import logging
import asyncio
from threading import RLock
from typing import Any
from common.redis_policy import redis_url
from common.features import enabled

MISSING = object()


class LookupCache:
    def __init__(self, ttl: float | None = None) -> None:
        self.ttl = float(os.getenv("BLADE_CACHE_TTL", "60")) if ttl is None else ttl
        if self.ttl <= 0:
            raise ValueError("Cache TTL must be positive")
        self._entries: dict[tuple[str, str], tuple[float, Any]] = {}
        self._lock = RLock()
        self._redis = None
        self._retry_at = 0.0
        self._dirty = False
        self._async_redis = None
        self._repair_lock = asyncio.Lock()
        self._generation = 0
        self._sweep_at = 0.0
        self._reads: dict[tuple[int, tuple[str, str]], asyncio.Future] = {}
        self._queued_reads: list[tuple[int, tuple[str, str], asyncio.Future]] = []
        self._flush_task: asyncio.Task | None = None
        self._io_tasks: set[asyncio.Task] = set()
        self._tracking_task: asyncio.Task | None = None
        self._tracking_ready = False
        self._tracking_revision = 0
        self._tracking_started = asyncio.Event()
        self._remote_keys: dict[str, tuple[str, str]] = {}
        self._known_remote_keys: set[str] = set()
        self._inventory_complete = False
        self._writes: dict[tuple[str, str], asyncio.Future] = {}
        self._queued_writes: list[tuple[tuple[str, str], Any, int, float, asyncio.Future]] = []
        self._write_task: asyncio.Task | None = None
        # Separate databases/projects even when they happen to share a Redis DB.
        namespace = hashlib.sha256(os.getenv('BLADE_DB_DSN', 'sqlite:///demo.db').encode()).hexdigest()[:16]
        self._prefix = 'blade:lookup:' + namespace + ':'
        if redis_url():
            try:
                import redis
                from redis.backoff import NoBackoff
                from redis.retry import Retry
                self._redis = redis.Redis.from_url(redis_url(), socket_connect_timeout=.1,
                                                  socket_timeout=.1, decode_responses=True,
                                                  retry=Retry(NoBackoff(), 0))
            except Exception:
                logging.warning('Redis lookup cache unavailable; using memory')

    def _remote(self) -> bool:
        return self._redis is not None and time.monotonic() >= self._retry_at

    def _failed(self) -> None:
        already_failed = time.monotonic() < self._retry_at
        self._retry_at = time.monotonic() + 5
        self._dirty = True
        self._tracking_ready = False
        if not already_failed:
            logging.warning('Redis lookup cache failed; using memory for 5 seconds')

    def _key(self, key: tuple[str, str]) -> str:
        result = self._prefix + hashlib.sha256(json.dumps(key).encode()).hexdigest()
        if self._tracking_ready:
            if len(self._remote_keys) >= 100000:
                self._remote_keys.clear()
                self._entries.clear()
            self._remote_keys[result] = key
        return result

    def _remember_remote_key(self, key: str) -> None:
        if not self._inventory_complete:
            return
        if len(self._known_remote_keys) >= 100000:
            self._inventory_complete = False
            self._known_remote_keys.clear()
            return
        self._known_remote_keys.add(key)

    async def start(self) -> None:
        if self._redis is not None and enabled('BLADE_REDIS_LOCAL_CACHE_ENABLED'):
            self._tracking_task = asyncio.create_task(self._track_invalidations())
            try:
                await asyncio.wait_for(self._tracking_started.wait(), 1)
            except asyncio.TimeoutError:
                pass

    async def _track_invalidations(self) -> None:
        from redis.asyncio import Redis
        from redis.asyncio.retry import Retry
        from redis.backoff import NoBackoff
        while True:
            try:
                async with Redis.from_url(redis_url(), decode_responses=True, socket_connect_timeout=.25,
                    socket_timeout=2, retry=Retry(NoBackoff(), 0), single_connection_client=True) as tracker:
                    async with self._async_client().pubsub() as subscription:
                        # RESP2 redirects server-assisted invalidations to this
                        # dedicated Pub/Sub connection; no server config changes.
                        await subscription.execute_command('CLIENT', 'ID')
                        receiver = await subscription.parse_response()
                        await subscription.subscribe('__redis__:invalidate')
                        await subscription.get_message(timeout=1)
                        await tracker.execute_command('CLIENT', 'TRACKING', 'ON', 'BCAST', 'PREFIX', self._prefix,
                                                      'REDIRECT', receiver)
                        self._known_remote_keys.clear()
                        self._inventory_complete = True
                        async for remote_key in tracker.scan_iter(match=self._prefix+'*', count=1000):
                            self._remember_remote_key(remote_key)
                            if not self._inventory_complete:
                                break
                        with self._lock:
                            self._entries.clear()
                            self._remote_keys.clear()
                            self._generation += 1
                        self._tracking_ready = True
                        self._tracking_started.set()
                        last_ping = time.monotonic()
                        while True:
                            message = await subscription.get_message(ignore_subscribe_messages=True, timeout=.25)
                            if message and message['type'] == 'message':
                                keys = message['data']
                                with self._lock:
                                    self._tracking_revision += 1
                                    if keys is None:
                                        self._entries.clear()
                                        self._known_remote_keys.clear()
                                    else:
                                        for remote_key in keys:
                                            # Deletions may conservatively stay in
                                            # this set; that costs a miss, never stale data.
                                            self._remember_remote_key(remote_key)
                                            key = self._remote_keys.get(remote_key)
                                            if key is not None:
                                                self._entries.pop(key, None)
                            if time.monotonic() - last_ping >= 1:
                                await tracker.ping()
                                last_ping = time.monotonic()
            except asyncio.CancelledError:
                raise
            except Exception:
                self._tracking_ready = False
                self._tracking_started.set()
                await asyncio.sleep(.5)
            finally:
                self._tracking_ready = False
                with self._lock:
                    self._entries.clear()

    def _repair(self) -> None:
        if self._dirty:
            # A write/cache clear may have occurred while Redis was disconnected.
            for key in self._redis.scan_iter(match=self._prefix + '*', count=100):
                self._redis.delete(key)
            self._dirty = False

    def get(self, key: tuple[str, str]) -> Any:
        with self._lock:
            if self._remote():
                try:
                    self._repair()
                    encoded = self._redis.get(self._key(key))
                    if encoded is not None:
                        signature, row = json.loads(encoded)
                        value = (tuple(signature), row)
                        # Redis owns the expiry; do not extend stale entries in fallback.
                        remaining = self._redis.pttl(self._key(key))
                        if remaining <= 0:
                            return MISSING
                        self._entries[key] = (time.monotonic() + remaining / 1000, value)
                        return value
                    self._entries.pop(key, None)
                    return MISSING
                except Exception:
                    self._failed()
            return self._get_memory(key)

    def _get_memory(self, key: tuple[str, str]) -> Any:
        entry = self._entries.get(key)
        if entry is None:
            return MISSING
        expires, value = entry
        if time.monotonic() >= expires:
            self._entries.pop(key, None)
            return MISSING
        return value

    def set(self, key: tuple[str, str], value: Any) -> None:
        with self._lock:
            self._set(key, value)

    def _set(self, key: tuple[str, str], value: Any) -> None:
        now = time.monotonic()
        # Reclaim expired keys even when they are never requested again.
        if now >= self._sweep_at:
            self._entries = {k: v for k, v in self._entries.items() if v[0] > now}
            self._sweep_at = now + min(1.0, self.ttl)
        self._entries[key] = (now + self.ttl, value)
        if self._remote():
            try:
                self._repair()
                self._redis.set(self._key(key), json.dumps(value), px=max(1, int(self.ttl * 1000)))
            except Exception:
                self._failed()

    def clear(self) -> None:
        with self._lock:
            self._generation += 1
            self._entries.clear()
            self._dirty = True
            if self._remote():
                try:
                    self._repair()
                except Exception:
                    self._failed()

    def _async_client(self) -> Any:
        if self._async_redis is None:
            from redis.asyncio import Redis
            from redis.backoff import NoBackoff
            from redis.asyncio.retry import Retry
            self._async_redis = Redis.from_url(redis_url(), socket_connect_timeout=.1,
                socket_timeout=.1, decode_responses=True, retry=Retry(NoBackoff(), 0))
        return self._async_redis

    async def _arepair(self) -> None:
        if not self._dirty:
            return
        async with self._repair_lock:
            if self._dirty:
                client = self._async_client()
                async for key in client.scan_iter(match=self._prefix + '*', count=100):
                    await client.delete(key)
                self._dirty = False

    async def aget(self, key: tuple[str, str]) -> Any:
        if self._tracking_ready and not self._dirty:
            with self._lock:
                value = self._get_memory(key)
                if value is not MISSING:
                    return value
            if self._inventory_complete and self._key(key) not in self._known_remote_keys:
                # The tracked namespace inventory proves this is a remote miss.
                # Ownership still comes from the authoritative DB.
                return MISSING
        pending = self._writes.get(key)
        if pending is not None:
            await asyncio.shield(pending)
        if self._remote():
            generation = self._generation
            try:
                await self._arepair()
                identity = (generation, key)
                future = self._reads.get(identity)
                if future is None:
                    future = asyncio.get_running_loop().create_future()
                    self._reads[identity] = future
                    self._queued_reads.append((generation, key, future))
                    if self._flush_task is None:
                        self._flush_task = asyncio.create_task(self._flush_reads())
                        self._io_tasks.add(self._flush_task)
                        self._flush_task.add_done_callback(self._io_tasks.discard)
                # Same-key requests share only an in-flight snapshot, never a
                # long-lived local hit that could conceal a remote invalidation.
                return await asyncio.shield(future)
            except Exception:
                self._failed()
        with self._lock:
            return self._get_memory(key)

    async def _flush_reads(self) -> None:
        batch = self._queued_reads
        self._queued_reads = []
        self._flush_task = None
        started = time.monotonic()
        revision = self._tracking_revision
        try:
            # Bound each atomic script so large bursts do not monopolize Redis.
            for offset in range(0, len(batch), 256):
                part = batch[offset:offset + 256]
                rows = await self._async_client().eval(
                    "local r={} for i,k in ipairs(KEYS) do "
                    "r[i]={redis.call('GET',k),redis.call('PTTL',k)} end return r",
                    len(part), *(self._key(key) for _, key, _ in part))
                for (generation, key, future), (encoded, remaining) in zip(part, rows):
                    value = MISSING
                    if generation == self._generation and revision == self._tracking_revision:
                        with self._lock:
                            if encoded and remaining > 0:
                                signature, row = json.loads(encoded)
                                self._entries[key] = (started + remaining / 1000, (tuple(signature), row))
                                value = self._get_memory(key)
                            else:
                                self._entries.pop(key, None)
                    if not future.done():
                        future.set_result(value)
        except Exception:
            self._failed()
            for generation, key, future in batch:
                if not future.done():
                    with self._lock:
                        future.set_result(self._get_memory(key) if generation == self._generation else MISSING)
        finally:
            for generation, key, future in batch:
                if not future.done():
                    future.cancel()
                self._reads.pop((generation, key), None)

    async def aset(self, key: tuple[str, str], value: Any, *, generation: int | None = None) -> None:
        generation = self._generation if generation is None else generation
        if generation != self._generation:
            return
        now = time.monotonic()
        with self._lock:
            if now >= self._sweep_at:
                self._entries = {k: v for k, v in self._entries.items() if v[0] > now}
                self._sweep_at = now + min(1.0, self.ttl)
            self._entries[key] = (now + self.ttl, value)
        if self._remote():
            future = asyncio.get_running_loop().create_future()
            self._writes[key] = future
            self._queued_writes.append((key, value, generation, now + self.ttl, future))
            if self._write_task is None:
                self._write_task = asyncio.create_task(self._flush_writes())
                self._io_tasks.add(self._write_task)
                self._write_task.add_done_callback(self._io_tasks.discard)

    async def _flush_writes(self) -> None:
        batch, self._queued_writes = self._queued_writes, []
        self._write_task = None
        try:
            await self._arepair()
            for offset in range(0, len(batch), 256):
                part = batch[offset:offset + 256]
                async with self._async_client().pipeline(transaction=False) as pipeline:
                    for key, value, generation, deadline, _ in part:
                        ttl_ms = int((deadline-time.monotonic()) * 1000)
                        if generation == self._generation and ttl_ms > 0:
                            pipeline.set(self._key(key), json.dumps(value), px=ttl_ms)
                    await pipeline.execute()
                for key, _, generation, _, _ in part:
                    if generation != self._generation:
                        await self._async_client().delete(self._key(key))
        except Exception:
            self._failed()
        finally:
            for key, _, _, _, future in batch:
                if self._writes.get(key) is future:
                    self._writes.pop(key, None)
                if not future.done(): future.set_result(None)

    @property
    def generation(self) -> int:
        return self._generation

    async def aclear(self) -> None:
        with self._lock:
            self._generation += 1
            self._entries.clear()
            self._dirty = True
        if self._remote():
            try:
                await self._arepair()
            except Exception:
                self._failed()

    async def aclose(self) -> None:
        if self._tracking_task is not None:
            self._tracking_task.cancel()
            await asyncio.gather(self._tracking_task, return_exceptions=True)
        if self._io_tasks:
            await asyncio.gather(*self._io_tasks, return_exceptions=True)
        if self._async_redis is not None:
            await self._async_redis.aclose()
        if self._redis is not None:
            self._redis.close()
