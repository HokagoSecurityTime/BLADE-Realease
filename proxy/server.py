"""Run with python -m proxy.server. No classifier or LLM imports."""
import asyncio
from contextlib import suppress
from datetime import datetime, timezone
import logging
import os
import uuid
from time import monotonic
from collections.abc import AsyncIterator

from aiohttp import web, ClientSession, ClientTimeout, ClientError, DummyCookieJar
from multidict import CIMultiDict
from yarl import URL

from common.labels import Label
from common.features import enabled
from proxy.observability import Observability
from common.redis_policy import PolicySubscriber, redis_url
from common.schema import Policy
from common.schema import DetectionLog, Verdict
from proxy.cache import LookupCache
from proxy.lookup import BatchedLookup
from proxy.router import Router
from proxy.evaluator import Decision, evaluate
from proxy.jwt_auth import authenticate
from common.redis_detections import client as delivery_client, stream_name


HOP = {'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
       'te', 'trailer', 'transfer-encoding', 'upgrade', 'proxy-connection', 'host', 'content-length'}


def headers_without_hop(headers: CIMultiDict) -> CIMultiDict:
    blocked = HOP | {v.strip().lower() for line in headers.getall('Connection', []) for v in line.split(',')}
    return CIMultiDict((k,v) for k,v in headers.items() if k.lower() not in blocked)


def create_app() -> web.Application:
    secret = os.environ.get('BLADE_JWT_SECRET', '')
    if not secret:
        raise ValueError('BLADE_JWT_SECRET is required')
    target = os.getenv('BLADE_TARGET_URL','http://127.0.0.1:9000').rstrip('/')
    admin = os.getenv('BLADE_ADMIN_URL','http://127.0.0.1:8100').rstrip('/')
    mode = os.getenv('BLADE_FAIL_MODE','open')
    if mode not in {'open','closed'}:
        raise ValueError('BLADE_FAIL_MODE must be open or closed')
    ttl = float(os.getenv('BLADE_CACHE_TTL','60'))
    poll = float(os.getenv('BLADE_POLICY_POLL_SEC','5'))
    if ttl <= 0 or poll <= 0:
        raise ValueError('TTL and poll interval must be positive')
    cache = LookupCache(ttl)
    lookup = BatchedLookup(os.getenv('BLADE_DB_DSN', 'sqlite:///demo.db')) if enabled('BLADE_LOOKUP_BATCH_ENABLED') else None
    router = Router()
    counters = Observability()
    reporter = str(uuid.uuid4())
    subscriber = PolicySubscriber()
    metrics_enabled = enabled('BLADE_OBSERVABILITY_ENABLED')
    queue: asyncio.Queue[DetectionLog] = asyncio.Queue(maxsize=10000)
    app = web.Application(client_max_size=0)

    async def lifecycle(app: web.Application) -> AsyncIterator[None]:
        nonlocal control, upstream
        control = ClientSession(timeout=ClientTimeout(total=5), cookie_jar=DummyCookieJar())
        upstream = ClientSession(timeout=ClientTimeout(total=60), auto_decompress=False, skip_auto_headers={'Accept-Encoding', 'Content-Type', 'User-Agent'}, cookie_jar=DummyCookieJar())
        delivery_redis = delivery_client()

        async def refresh() -> None:
            try:
                previous = router.routes
                await router.refresh(control, admin)
                if previous != router.routes:
                    await clear_cache()
            except (ClientError, ValueError, TypeError, asyncio.TimeoutError):
                logging.warning('Policy refresh failed; last valid snapshot retained')

        async def poller() -> None:
            reconciled = monotonic()
            while True:
                await asyncio.sleep(poll)
                if not subscriber.connected or monotonic() - reconciled >= 60:
                    await refresh()
                    reconciled = monotonic()

        async def apply_snapshot(policies: list[Policy]) -> None:
            snapshot = Router(policies).routes
            if snapshot != router.routes:
                router.routes = snapshot
                await clear_cache()

        async def logger() -> None:
            while True:
                record = await queue.get()
                try:
                    async with control.post(admin+'/detections', json=record.model_dump(mode='json')) as response:
                        response.raise_for_status()
                except (ClientError, asyncio.TimeoutError):
                    logging.error('Detection delivery failed: request_id=%s', record.request_id)
                finally:
                    queue.task_done()

        async def metrics_sender() -> None:
            while True:
                await asyncio.sleep(1)
                snapshot = counters.snapshot()
                snapshot.pop('rate')
                try:
                    async with control.post(admin + '/metrics/observability',
                                            json={'reporter': reporter, **snapshot}) as response:
                        response.raise_for_status()
                except (ClientError, asyncio.TimeoutError):
                    logging.warning('Observability delivery failed')

        async def stream_logger() -> None:
            destination = stream_name()
            while True:
                batch = [await queue.get()]
                await asyncio.sleep(.002)
                while len(batch) < 256:
                    try:
                        batch.append(queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                try:
                    # One transport entry per batch; individual detection schemas
                    # and request IDs remain unchanged for storage and replay.
                    payload = '[' + ','.join(record.model_dump_json() for record in batch) + ']'
                    await delivery_redis.xadd(destination, {'records': payload})
                except Exception:
                    # Fall back to the existing API during a Redis outage.
                    for record in batch:
                        try:
                            async with control.post(admin+'/detections', json=record.model_dump(mode='json')) as response:
                                response.raise_for_status()
                        except (ClientError, asyncio.TimeoutError):
                            logging.error('Detection delivery failed: request_id=%s', record.request_id)
                finally:
                    for _ in batch:
                        queue.task_done()

        await cache.start()
        await refresh()
        sender_count = 64 if enabled('BLADE_DETECTION_BATCH_ENABLED') else 1
        tasks = [asyncio.create_task(poller())]
        tasks += ([asyncio.create_task(stream_logger())] if delivery_redis is not None else
                  [asyncio.create_task(logger()) for _ in range(sender_count)])
        if metrics_enabled:
            tasks.append(asyncio.create_task(metrics_sender()))
        if subscriber.url:
            tasks.append(asyncio.create_task(subscriber.run(apply_snapshot, refresh)))
        try:
            yield
        finally:
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(queue.join(), 30 if enabled('BLADE_DETECTION_BATCH_ENABLED') else 5)
            if not queue.empty():
                logging.error('Detection shutdown incomplete: %s queued records remain', queue.qsize())
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await control.close()
            await upstream.close()
            if delivery_redis is not None:
                await delivery_redis.aclose()
            await cache.aclose()
            if lookup is not None:
                await lookup.close()

    control: ClientSession
    upstream: ClientSession
    app.cleanup_ctx.append(lifecycle)

    async def clear_cache() -> None:
        if redis_url():
            await cache.aclear()
        else:
            cache.clear()

    async def handle(request: web.Request) -> web.StreamResponse:
        match = router.match(request.method, request.path)
        policy, params = match if match else (None, {})
        claims = authenticate(request.headers.get('Authorization'), secret)
        decision = (await evaluate(policy, claims, params, request.query, lookup=lookup, cache=cache, fail_mode=mode)
                    if policy else Decision(Verdict.OBSERVE, 'no_policy'))
        if metrics_enabled:
            counters.record(policy is not None, decision.lookup_ok)
        record = DetectionLog(ts=datetime.now(timezone.utc), request_id=str(uuid.uuid4()),
            sub=claims.sub if claims else '', method=request.method, path=request.path,
            policy_id=policy.id if policy else '', label=policy.label if policy else Label.MANUAL_REVIEW_REQUIRED,
            verdict=decision.verdict, reason=decision.reason,
            mode=(policy.mode if policy else 'observe') if enabled('BLADE_MODE_ENABLED') else 'enforce',
            would_block=decision.would_block)
        try:
            queue.put_nowait(record)
        except asyncio.QueueFull:
            if enabled('BLADE_DETECTION_BATCH_ENABLED'):
                # Apply bounded-memory backpressure instead of discarding logs.
                await queue.put(record)
            else:
                logging.error('Detection queue full: request_id=%s', record.request_id)
        debug_headers = {'X-Blade-Request-Id': record.request_id}
        if policy:
            debug_headers['X-Blade-Policy'] = policy.id
        if decision.verdict == Verdict.BLOCK:
            return web.json_response({'error': 'forbidden', 'policy_id': record.policy_id,
                                      'request_id': record.request_id}, status=403, headers=debug_headers)
        try:
            async with upstream.request(request.method, URL(target+request.raw_path, encoded=True),
                headers=headers_without_hop(request.headers), data=await request.read(), allow_redirects=False) as response:
                if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
                    await clear_cache()
                headers = headers_without_hop(response.headers)
                headers['X-Blade-Request-Id'] = record.request_id
                headers.popall('X-Blade-Policy', None)
                if policy:
                    headers['X-Blade-Policy'] = policy.id
                return web.Response(status=response.status, headers=headers, body=await response.read())
        except (ClientError, asyncio.TimeoutError):
            return web.json_response({'detail':'Upstream unavailable'}, status=502)

    app.router.add_route('*','/{path:.*}',handle)
    return app


if __name__ == '__main__':
    web.run_app(create_app(), host=os.getenv('BLADE_PROXY_HOST', '127.0.0.1'), port=8080)
