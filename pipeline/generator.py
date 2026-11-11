"""Convert offline classifications into reviewable PENDING policy files."""

from datetime import datetime, timezone
from pathlib import Path
import re
import tempfile
import os

from common.schema import Endpoint as PolicyEndpoint, Policy, PolicyParams, PolicyStatus, policy_to_yaml
from pipeline.classifier.schema import ClassificationResult
from pipeline.parsers.oas import Endpoint


def policy_id(endpoint: Endpoint) -> str:
    """Use static path segments as resource; preserve parameter spelling."""
    resource = '_'.join(part for part in endpoint.path.strip('/').split('/')
                        if part and not part.startswith('{')) or 'root'
    params = endpoint.path_params or endpoint.query_params
    identifier = f'pol_{resource}_{endpoint.method.lower()}'
    if params:
        identifier += '_by_' + '_'.join(params)
    return re.sub(r'[^A-Za-z0-9_]', '_', identifier)


def build_policy(endpoint: Endpoint, result: ClassificationResult, *, created_at: datetime | None = None) -> Policy:
    return Policy(
        id=policy_id(endpoint), endpoint=PolicyEndpoint(method=endpoint.method, path=endpoint.path),
        label=result.label, params=PolicyParams(
            object_param=result.object_param, owner_lookup=result.owner_lookup,
            roles=result.roles, allowed_membership=result.allowed_membership),
        confidence=result.confidence, evidence=result.evidence, status=PolicyStatus.PENDING,
        created_at=created_at or datetime.now(timezone.utc),
        evidence_refs=result.evidence_refs,
    )


def save_policy(policy: Policy, output_dir: str | Path = 'policies') -> Path:
    if not re.fullmatch(r'pol_[A-Za-z0-9_]+', policy.id):
        raise ValueError('Unsafe policy id')
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f'{policy.id}.yaml'
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory, delete=False) as stream:
            temporary = stream.name
            stream.write(policy_to_yaml(policy))
        os.replace(temporary, destination)
    finally:
        if temporary and Path(temporary).exists():
            Path(temporary).unlink()
    return destination


def generate_policy(endpoint: Endpoint, result: ClassificationResult, output_dir: str | Path = 'policies') -> Policy:
    policy = build_policy(endpoint, result)
    save_policy(policy, output_dir)
    return policy
