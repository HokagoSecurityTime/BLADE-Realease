from datetime import datetime
from enum import StrEnum
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SerializationInfo, SerializerFunctionWrapHandler, model_serializer
from common.features import enabled

from common.labels import Label


class SchemaModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicyStatus(StrEnum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"


class Verdict(StrEnum):
    PASS = "PASS"
    BLOCK = "BLOCK"
    OBSERVE = "OBSERVE"


class Endpoint(SchemaModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]
    path: str


class OwnerLookup(SchemaModel):
    table: str
    id_col: str
    owner_col: str | None = None
    tenant_col: str | None = None


class PolicyParams(SchemaModel):
    object_param: str | None = None
    owner_lookup: OwnerLookup | None = None
    roles: list[str] = Field(default_factory=list)
    allowed_membership: list[str] = Field(default_factory=list)


class EvidenceRef(SchemaModel):
    kind: Literal['code', 'idiom', 'policy', 'cve']
    ref: str
    snippet: str


class Policy(SchemaModel):
    id: str
    endpoint: Endpoint
    label: Label
    params: PolicyParams
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    status: PolicyStatus
    created_at: datetime
    mode: Literal['observe', 'enforce'] = 'observe'
    version: int = Field(default=1, ge=1)
    source: Literal['llm', 'manual', 'reanalysis'] = 'llm'
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)


class JWTClaims(SchemaModel):
    sub: str
    roles: list[str]
    tenant_id: str
    membership: str
    exp: int


class DetectionLog(SchemaModel):
    ts: datetime
    request_id: str
    sub: str
    method: str
    path: str
    policy_id: str
    label: Label
    verdict: Verdict
    reason: str
    mode: Literal['observe', 'enforce'] = 'observe'
    explanation: str | None = None
    would_block: bool = False

    @model_serializer(mode='wrap')
    def serialize(self, handler: SerializerFunctionWrapHandler, info: SerializationInfo) -> dict:
        data = handler(self)
        # Preserve the Phase 1 wire/JSONL shape when all Phase 2 features are off.
        # SQLite explicitly requests the complete shape for additive migrations.
        if not enabled('BLADE_PHASE2_ENABLED') and not (info.context or {}).get('storage'):
            for name in ('mode', 'explanation', 'would_block'):
                data.pop(name, None)
        return data


def policy_from_yaml(document: str) -> Policy:
    return Policy.model_validate(yaml.safe_load(document))


def policy_to_yaml(policy: Policy) -> str:
    return yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False, allow_unicode=True)
