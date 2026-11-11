"""Offline proposals only: no automatic approval, enforcement or live policy edits."""
import asyncio
from collections import defaultdict
import logging
import os
import re

from admin_api.proposals import Proposals
from admin_api.store import Store
from common.features import enabled
from common.schema import Policy, policy_to_yaml
from pipeline.classifier import classify
from pipeline.generator import build_policy
from pipeline.parsers.erd import ForeignKey, TableInfo
from pipeline.parsers.oas import Endpoint


def summarize(policy: Policy, rows: list[dict]) -> dict:
    pattern = re.sub(r'\\\{[^}]+\\\}', r'([^/]+)', re.escape(policy.endpoint.path))
    fingerprints = set()
    subjects, objects = set(), set()
    for row in rows:
        if row['verdict'] != 'OBSERVE' and not row.get('would_block'):
            continue
        match = re.fullmatch(pattern, row['path'])
        identifiers = match.groups() if match else ()
        subjects.add(row['sub']); objects.update(identifiers)
        # Raw values exist only within this function to deduplicate patterns.
        fingerprints.add((row['sub'], identifiers, row['method'], row['verdict'], bool(row.get('would_block'))))
    return dict(unique_patterns=len(fingerprints), distinct_subjects=len(subjects), distinct_object_ids=len(objects),
                observe_count=sum(r['verdict']=='OBSERVE' for r in rows),
                would_block_count=sum(bool(r.get('would_block')) for r in rows),
                route=policy.endpoint.path, roles='unknown: detection schema does not contain JWT roles',
                note='Subject/object values masked. Counts alone do not prove ownership or an administrator bypass.')


def trigger(policy: Policy, rows: list[dict], rollback: bool = False) -> str | None:
    if not enabled('BLADE_REANALYSIS_ENABLED') or policy.status == 'REJECTED':
        return None
    if rollback:
        return 'rollback'
    threshold = max(1, int(os.getenv('BLADE_REANALYSIS_OBSERVE_THRESHOLD', '20')))
    if policy.label == 'manual_review_required' and sum(r['verdict']=='OBSERVE' for r in rows) >= threshold:
        return 'manual_review_observe_threshold'
    minimum = max(1, int(os.getenv('BLADE_REANALYSIS_MIN_REQUESTS', '5')))
    subjects = max(1, int(os.getenv('BLADE_REANALYSIS_MIN_SUBJECTS', '3')))
    ratio = float(os.getenv('BLADE_REANALYSIS_WOULD_BLOCK_RATIO', '0.8'))
    if not 0 <= ratio <= 1:
        raise ValueError('BLADE_REANALYSIS_WOULD_BLOCK_RATIO must be between 0 and 1')
    by_sub: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        if row['mode'] == 'observe' and row['sub']:
            by_sub[row['sub']].append(row)
    suspicious = sum(len(group)>=minimum and sum(bool(r.get('would_block')) for r in group)/len(group)>=ratio
                     for group in by_sub.values())
    return 'high_would_block_ratio' if policy.mode == 'observe' and suspicious >= subjects else None


def run_once(store: Store) -> list[dict]:
    if not enabled('BLADE_REANALYSIS_ENABLED'):
        return []
    proposals = Proposals(store)
    created = []
    for policy in store.list_policies():
        rows, rowid, event = proposals.inputs(policy.id)
        reason = trigger(policy, rows, proposals.rollback_pending(policy.id, event))
        if not reason or not proposals.claim(policy.id):
            continue
        try:
            context = proposals.context(policy.id)
            if context is None:
                raise ValueError('Missing generation context; regenerate/import context before reanalysis')
            endpoint = Endpoint(**context['endpoint'])
            erd = {name: TableInfo(**{**table, 'fks': [ForeignKey(**fk) for fk in table['fks']]}) for name,table in context['erd'].items()}
            result = classify(endpoint, erd, context.get('controller'), analysis_context={
                'original_policy': policy_to_yaml(policy), 'trigger': reason, 'traffic_summary': summarize(policy, rows)})
            if result.evidence.startswith('LLM unavailable:'):
                raise RuntimeError('LLM unavailable')
            proposed = build_policy(endpoint, result, created_at=policy.created_at).model_copy(update={
                'id': policy.id, 'status': policy.status, 'source': 'reanalysis', 'version': policy.version+1, 'mode': 'observe'})
            created.append(proposals.create(policy, proposed, reason))
            proposals.finish(policy.id, rowid, event)
        except Exception as exc:
            logging.warning('Reanalysis failed policy_id=%s (%s)', policy.id, type(exc).__name__)
            proposals.release(policy.id)
    return created


async def run(store: Store) -> None:
    while True:
        try:
            await asyncio.to_thread(run_once, store)
        except Exception as exc:
            logging.warning('Reanalysis scan failed (%s)', type(exc).__name__)
        await asyncio.sleep(max(.1, float(os.getenv('BLADE_REANALYSIS_POLL_SEC', '5'))))
