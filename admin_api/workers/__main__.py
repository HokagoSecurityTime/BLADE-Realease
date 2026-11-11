"""Independent workers: python -m admin_api.workers. No proxy dependencies."""
import asyncio
import logging
import os

import aiohttp

from admin_api.store import Store
from admin_api.workers.alerts import AlertWorker
from admin_api.workers.explain import explain
from common.features import enabled


async def detection_worker(store: Store, kind: str, session: aiohttp.ClientSession) -> None:
    alerts = AlertWorker()
    while True:
        try:
            if enabled('BLADE_' + kind.upper() + '_ENABLED'):
                batch = await asyncio.to_thread(store.worker_batch, kind)
                for seq, record in batch:
                    if kind == 'alerts':
                        await alerts.notify(record, session, await asyncio.to_thread(store.alert_settings))
                    else:
                        await explain(record, session, os.getenv('BLADE_ADMIN_URL', 'http://localhost:8100'))
                    await asyncio.to_thread(store.checkpoint_worker, kind, seq)
        except Exception as exc:
            logging.warning('%s worker failed (%s)', kind, type(exc).__name__)
        await asyncio.sleep(0.5)


async def run() -> None:
    if not enabled('BLADE_PHASE2_ENABLED'):
        logging.info('Phase 2 workers disabled')
        return
    store = Store(os.getenv('BLADE_ADMIN_DB', 'blade.db'), os.getenv('BLADE_POLICY_DIR', 'policies'),
                  os.getenv('BLADE_DETECTION_FILE', 'detections.jsonl'))
    await asyncio.to_thread(store.initialize)
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
        from admin_api.workers.reanalysis import run as reanalysis
        await asyncio.gather(detection_worker(store, 'alerts', session), detection_worker(store, 'explain', session), reanalysis(store))


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    asyncio.run(run())
