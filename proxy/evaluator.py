"""Policy evaluation; ownership I/O runs off the event loop."""
from collections.abc import Mapping
from dataclasses import dataclass
import os
import asyncio

from common.labels import Label
from common.features import enabled
from common.redis_policy import redis_url
from common.schema import JWTClaims, Policy, Verdict
from proxy.cache import LookupCache, MISSING
from proxy.lookup import BatchedLookup, Lookup, LookupError


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    would_block: bool = False
    lookup_ok: bool = False


async def evaluate(
    policy: Policy, claims: JWTClaims | None,
    path_params: Mapping[str, str], query: Mapping[str, str], *,
    lookup: Lookup | BatchedLookup | None = None, cache: LookupCache | None = None,
    fail_mode: str | None = None,
) -> Decision:
    decision = await _evaluate(policy, claims, path_params, query, lookup=lookup, cache=cache, fail_mode=fail_mode)
    if enabled('BLADE_MODE_ENABLED') and policy.mode == 'observe' and decision.verdict == Verdict.BLOCK:
        return Decision(Verdict.OBSERVE, decision.reason, would_block=True, lookup_ok=decision.lookup_ok)
    return decision


async def _evaluate(
    policy: Policy, claims: JWTClaims | None,
    path_params: Mapping[str, str], query: Mapping[str, str], *,
    lookup: Lookup | BatchedLookup | None = None, cache: LookupCache | None = None,
    fail_mode: str | None = None,
) -> Decision:
    lookup_ok = False
    mode = fail_mode or os.getenv('BLADE_FAIL_MODE', 'open')
    if mode not in {'open', 'closed'}:
        raise ValueError('BLADE_FAIL_MODE must be open or closed')
    label = policy.label
    if label == Label.PUBLIC:
        return Decision(Verdict.PASS, 'public')
    if claims is None:
        return Decision(Verdict.BLOCK, 'no_token')
    if label == Label.MANUAL_REVIEW_REQUIRED:
        return Decision(Verdict.OBSERVE, 'manual_review_required')
    if label == Label.ROLE_REQUIRED:
        allowed = bool(set(claims.roles) & set(policy.params.roles))
    elif label == Label.MEMBERSHIP_REQUIRED:
        allowed = claims.membership in policy.params.allowed_membership
    elif label == Label.OWNER_OR_ADMIN and 'admin' in claims.roles:
        return Decision(Verdict.PASS, 'admin_bypass')
    else:
        param = policy.params.object_param
        identifier = path_params.get(param) if param else None
        if identifier is None and param:
            values = query.getall(param, []) if hasattr(query, 'getall') else [query.get(param)]
            if len(values) == 1:
                identifier = values[0]
        if identifier is None or identifier == '':
            return Decision(Verdict.BLOCK, 'missing_object_param')
        try:
            spec = policy.params.owner_lookup
            if spec is None:
                raise LookupError('Missing lookup configuration')
            column = spec.tenant_col if label == Label.TENANT_MATCH else spec.owner_col
            if not column:
                raise LookupError('Missing ownership column')
            key = (spec.table, str(identifier))
            # Validate the projection too: policies can use different identifiers/columns.
            signature = (spec.id_col, spec.owner_col, spec.tenant_col)
            cached = MISSING
            generation = cache.generation if cache is not None else None
            if cache is not None:
                cached = await cache.aget(key) if redis_url() else cache.get(key)
            if cached is not MISSING and cached[0] == signature:
                row = cached[1]
            else:
                source = lookup or Lookup(os.getenv('BLADE_DB_DSN', 'sqlite:///demo.db'))
                row = await source.get(spec, str(identifier))
                if cache is not None:
                    if redis_url():
                        await cache.aset(key, (signature, row), generation=generation)
                    else:
                        cache.set(key, (signature, row))
            if row is None:
                return Decision(Verdict.PASS, 'object_not_found', lookup_ok=True)
            if column not in row:
                raise LookupError('Unknown ownership column')
            expected = claims.tenant_id if label == Label.TENANT_MATCH else claims.sub
            allowed = row[column] is not None and str(row[column]) == expected
            lookup_ok = True
        except Exception:
            return Decision(Verdict.OBSERVE if mode == 'open' else Verdict.BLOCK, 'lookup_failed')
    return Decision(Verdict.PASS if allowed else Verdict.BLOCK,
                    'policy_matched' if allowed else 'policy_mismatch', lookup_ok=lookup_ok)
