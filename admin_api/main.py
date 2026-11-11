"""Internal policy administration service: uvicorn admin_api.main:app --port 8100."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from dataclasses import asdict
import os
import asyncio
from contextlib import suppress
from threading import Lock
from pathlib import Path
from typing import Annotated
from typing import Literal
from threading import RLock
from time import monotonic

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool
import yaml

from admin_api.store import ConflictError, NotFoundError, Store
from common.labels import Label
from common.features import enabled
from common.schema import EvidenceRef
from common.schema import DetectionLog, Endpoint, Policy, PolicyParams, PolicyStatus
from pipeline import classifier, generator
from pipeline.parsers.erd import parse_erd
from pipeline.parsers.oas import parse_oas

_rag_lock = Lock()


class PolicyUpdate(BaseModel):
    """Full policy content without status; id and creation time are immutable."""
    model_config = ConfigDict(extra='forbid')
    id: str
    endpoint: Endpoint
    label: Label
    params: PolicyParams
    confidence: float = Field(ge=0, le=1)
    evidence: str
    created_at: datetime
    mode: Literal['observe', 'enforce'] = 'observe'
    version: int = Field(default=1, ge=1)
    source: Literal['llm', 'manual', 'reanalysis'] = 'llm'
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class ModeUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mode: Literal['observe', 'enforce']


class AlertSettings(BaseModel):
    model_config = ConfigDict(extra='forbid')
    slack_webhook: str = ''
    discord_webhook: str = ''
    min_severity: Literal['observe', 'block'] = 'observe'

    @field_validator('slack_webhook', 'discord_webhook')
    @classmethod
    def webhook(cls, value: str) -> str:
        from urllib.parse import urlsplit
        if value and (urlsplit(value).scheme not in ('http', 'https') or not urlsplit(value).hostname):
            raise ValueError('Use an HTTP(S) webhook URL')
        return value


class ExplanationUpdate(BaseModel):
    explanation: str = Field(min_length=1, max_length=1000)


class MetricsUpdate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    reporter: str = Field(min_length=1, max_length=100)
    total: int = Field(ge=0)
    with_policy: int = Field(ge=0)
    lookup_ok: int = Field(ge=0)


def create_app(db_path: str | Path = 'blade.db', policy_dir: str | Path = 'policies',
               detection_file: str | Path = 'detections.jsonl') -> FastAPI:
    store = Store(db_path, policy_dir, detection_file)
    deliveries: dict[asyncio.AbstractEventLoop, asyncio.Queue] = {}

    async def detection_writer(delivery: asyncio.Queue) -> None:
        while True:
            batch = [await delivery.get()]
            # Group concurrent single-record HTTP calls into one durable commit.
            await asyncio.sleep(.002)
            while len(batch) < 128:
                try:
                    batch.append(delivery.get_nowait())
                except asyncio.QueueEmpty:
                    break
            try:
                await run_in_threadpool(store.append_detections, [item[0] for item in batch], deduplicate=True)
            except Exception as exc:
                for _, done in batch:
                    if not done.done(): done.set_exception(exc)
            else:
                for record, done in batch:
                    if not done.done(): done.set_result(record)
            finally:
                for _ in batch: delivery.task_done()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        store.initialize()
        from common.redis_detections import consume
        stream_stop = asyncio.Event()
        stream_worker = asyncio.create_task(consume(store, stream_stop))
        loop = asyncio.get_running_loop()
        delivery: asyncio.Queue = asyncio.Queue(maxsize=2048)
        writer = asyncio.create_task(detection_writer(delivery)) if enabled('BLADE_DETECTION_BATCH_ENABLED') else None
        if writer is not None:
            deliveries[loop] = delivery
        try:
            yield
        finally:
            stream_stop.set()
            try:
                await asyncio.wait_for(stream_worker, 30)
            except asyncio.TimeoutError:
                import logging
                logging.error('Detection stream shutdown timed out; pending entries retained in Redis')
            if writer is not None:
                await delivery.join()
                writer.cancel()
                with suppress(asyncio.CancelledError):
                    await writer
                deliveries.pop(loop, None)

    app = FastAPI(title='BLADE policy administration', lifespan=lifespan)
    app.state.store = store
    metrics: dict[str, tuple[float, MetricsUpdate]] = {}
    metrics_lock = RLock()

    def require_feature(name: str) -> None:
        if not enabled(name):
            raise HTTPException(status_code=404, detail='Phase 2 feature disabled')

    @app.get('/features')
    def features() -> dict[str, bool]:
        return {name: enabled('BLADE_' + name.upper() + '_ENABLED') for name in
                ('phase2', 'mode', 'observability', 'alerts', 'explain', 'rag', 'reanalysis')}

    @app.get('/policies/{id}/proposals')
    def proposals(id: str) -> list[dict]:
        from admin_api.proposals import Proposals
        require_feature('BLADE_REANALYSIS_ENABLED')
        return Proposals(store).list(id)

    @app.post('/proposals/{pid}/accept', response_model=Policy)
    def accept_proposal(pid: int) -> Policy:
        from admin_api.proposals import Proposals
        require_feature('BLADE_REANALYSIS_ENABLED')
        return Proposals(store).decide(pid, True)

    @app.post('/proposals/{pid}/dismiss')
    def dismiss_proposal(pid: int) -> dict:
        from admin_api.proposals import Proposals
        require_feature('BLADE_REANALYSIS_ENABLED')
        return Proposals(store).decide(pid, False)

    @app.get('/settings/alerts', response_model=AlertSettings)
    def alert_settings() -> dict:
        require_feature('BLADE_ALERTS_ENABLED')
        return store.alert_settings()

    @app.put('/settings/alerts', response_model=AlertSettings)
    def save_alert_settings(body: AlertSettings) -> dict:
        require_feature('BLADE_ALERTS_ENABLED')
        return store.save_alert_settings(body.model_dump())

    @app.post('/settings/alerts/test')
    async def test_alert() -> dict:
        import aiohttp
        from uuid import uuid4
        from datetime import timezone
        from admin_api.workers.alerts import AlertWorker
        require_feature('BLADE_ALERTS_ENABLED')
        settings = await run_in_threadpool(store.alert_settings)
        if not (settings['slack_webhook'] or settings['discord_webhook']):
            raise HTTPException(status_code=400, detail='Configure a webhook first')
        record = DetectionLog(ts=datetime.now(timezone.utc), request_id=str(uuid4()), sub='test', method='GET',
            path='/test', policy_id='pol_test_get', label='owner_match', verdict='BLOCK', reason='notification_test', mode='enforce')
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            sent = await AlertWorker().notify(record, session, settings)
        return {'delivered': sent}

    @app.post('/detections/{id}/explanation', response_model=DetectionLog)
    def set_explanation(id: str, body: ExplanationUpdate) -> DetectionLog:
        require_feature('BLADE_EXPLAIN_ENABLED')
        return store.set_explanation(id, body.explanation)

    @app.post('/policies/{id}/mode', response_model=Policy)
    def change_mode(id: str, body: ModeUpdate) -> Policy:
        require_feature('BLADE_MODE_ENABLED')
        return store.update(id, mode=body.mode)

    @app.post('/metrics/observability')
    def receive_metrics(body: MetricsUpdate) -> dict[str, bool]:
        require_feature('BLADE_OBSERVABILITY_ENABLED')
        if not body.lookup_ok <= body.with_policy <= body.total:
            raise HTTPException(status_code=422, detail='Counters must satisfy lookup_ok <= with_policy <= total')
        with metrics_lock:
            metrics[body.reporter] = (monotonic(), body)
        return {'accepted': True}

    @app.get('/metrics/observability')
    def observability() -> dict[str, int | float]:
        require_feature('BLADE_OBSERVABILITY_ENABLED')
        with metrics_lock:
            for key in list(metrics):
                if monotonic() - metrics[key][0] >= 60:
                    del metrics[key]
            total = sum(value.total for _, value in metrics.values())
            matched = sum(value.with_policy for _, value in metrics.values())
            lookup = sum(value.lookup_ok for _, value in metrics.values())
        return dict(total=total, with_policy=matched, lookup_ok=lookup, rate=matched / total if total else 0.0)

    @app.exception_handler(NotFoundError)
    async def not_found(request: object, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={'detail': str(exc)})

    @app.exception_handler(ConflictError)
    async def conflict(request: object, exc: ConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={'detail': str(exc)})

    @app.get('/policies', response_model=list[Policy])
    def policies(status: PolicyStatus | None = None) -> list[Policy]:
        return store.list_policies(status)

    @app.get('/policies/{id}', response_model=Policy)
    def get_policy(id: str) -> Policy:
        return store.get(id)

    @app.get('/evidence/{policy_id}', response_model=list[EvidenceRef])
    def evidence(policy_id: str) -> list[EvidenceRef]:
        require_feature('BLADE_RAG_ENABLED')
        return store.get(policy_id).evidence_refs

    @app.put('/policies/{id}', response_model=Policy)
    def edit_policy(id: str, body: PolicyUpdate) -> Policy:
        return store.update(id, changes=body.model_dump())

    @app.post('/policies/{id}/approve', response_model=Policy)
    def approve(id: str) -> Policy:
        return store.update(id, transition=(PolicyStatus.PENDING, PolicyStatus.ACTIVE))

    @app.post('/policies/{id}/reject', response_model=Policy)
    def reject(id: str) -> Policy:
        return store.update(id, transition=(PolicyStatus.PENDING, PolicyStatus.REJECTED))

    @app.post('/policies/{id}/rollback', response_model=Policy)
    def rollback(id: str) -> Policy:
        return store.update(id, transition=(PolicyStatus.ACTIVE, PolicyStatus.PENDING))

    @app.post('/generate', response_model=list[Policy])
    async def generate(oas: Annotated[UploadFile, File()], erd: Annotated[UploadFile, File()],
                       controller: Annotated[UploadFile | None, File()] = None,
                       code_archive: Annotated[UploadFile | None, File(alias='code')] = None) -> list[Policy]:
        try:
            endpoints = parse_oas((await oas.read()).decode('utf-8-sig'))
            tables = parse_erd((await erd.read()).decode('utf-8-sig'))
            code = (await controller.read()).decode('utf-8-sig') if controller else None
            code_chunks = []
            if enabled('BLADE_RAG_ENABLED'):
                from pipeline.rag.corpus import load_zip, load_code
                if code_archive:
                    code_chunks.extend(load_zip(await code_archive.read()))
                if code:
                    code_chunks.extend(load_code(code, Path(controller.filename or 'controller.py').name))
        except (ValueError, yaml.YAMLError) as exc:
            raise HTTPException(status_code=422, detail='Invalid OAS, ERD or UTF-8 upload') from exc
        if not endpoints or not tables:
            raise HTTPException(status_code=422, detail='OAS endpoints and ERD tables must not be empty')
        ids = [generator.policy_id(endpoint) for endpoint in endpoints]
        existing = {policy.id for policy in await run_in_threadpool(store.list_policies)}
        if len(ids) != len(set(ids)) or existing.intersection(ids):
            raise ConflictError('Generated policy ids collide or already exist')

        def generate_batch() -> list[Policy]:
            # Intentionally sequential; move blocking LLM calls off the ASGI event loop.
            contexts = None
            if enabled('BLADE_RAG_ENABLED'):
                from pipeline.rag.index import Index
                from pipeline.rag.corpus import load_idioms, load_policies, load_cves
                try:
                    with _rag_lock:
                        index = Index()
                        index.replace('code', code_chunks)
                        index.replace('idiom', load_idioms())
                        index.replace('policy', load_policies(store.list_policies(PolicyStatus.ACTIVE)))
                        index.replace('cve', load_cves(Path(os.getenv('BLADE_CVE_CORPUS', 'corpus/cve.jsonl'))))
                        kinds = [k.strip() for k in os.getenv('BLADE_RAG_KINDS', 'code,idiom,policy,cve').split(',') if k.strip()]
                        contexts = [index.retrieve(endpoint, tables, kinds=kinds) for endpoint in endpoints]
                except Exception as exc:
                    raise HTTPException(status_code=503, detail='RAG initialization or retrieval failed; check server configuration') from exc
            batch = []
            for position, endpoint in enumerate(endpoints):
                result = (classifier.classify(endpoint, tables, code, evidence_refs=contexts[position]) if contexts is not None
                          else classifier.classify(endpoint, tables, code))
                batch.append(generator.build_policy(endpoint, result))
            saved_contexts = {generator.policy_id(e): dict(endpoint=asdict(e), erd={k: asdict(v) for k,v in tables.items()}, controller=code) for e in endpoints}
            return store.insert_many(batch, saved_contexts)

        return await run_in_threadpool(generate_batch)

    @app.get('/detections', response_model=list[DetectionLog])
    def detections(limit: Annotated[int, Query(ge=1, le=10000)] = 100) -> list[DetectionLog]:
        return store.list_detections(limit)

    @app.post('/detections', response_model=DetectionLog)
    async def add_detection(body: DetectionLog) -> DetectionLog:
        delivery = deliveries.get(asyncio.get_running_loop())
        if delivery is None:
            if enabled('BLADE_DETECTION_STREAM_ENABLED'):
                await run_in_threadpool(store.append_detections, [body], deduplicate=True)
                return body
            return await run_in_threadpool(store.append_detection, body)
        done = asyncio.get_running_loop().create_future()
        await delivery.put((body, done))
        return await asyncio.shield(done)

    return app


app = create_app()
