from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from common.labels import Label
from common.schema import OwnerLookup, EvidenceRef


class ClassificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: Label
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False, strict=True)
    evidence: str = Field(min_length=1)
    object_param: str | None
    owner_lookup: OwnerLookup | None
    roles: list[str]
    allowed_membership: list[str]
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def unknown_label(cls, data: Any) -> Any:
        if isinstance(data, dict) and (not isinstance(data.get("label"), str)
                                      or data["label"] not in {label.value for label in Label}):
            data = {**data, "label": Label.MANUAL_REVIEW_REQUIRED}
        return data

    @model_validator(mode="after")
    def low_confidence(self) -> Self:
        if self.confidence < 0.7:
            self.label = Label.MANUAL_REVIEW_REQUIRED
        if self.label == Label.MANUAL_REVIEW_REQUIRED:
            self.object_param = None
            self.owner_lookup = None
            self.roles = []
            self.allowed_membership = []
        return self


def manual_review(reason: str) -> ClassificationResult:
    return ClassificationResult(label=Label.MANUAL_REVIEW_REQUIRED, confidence=0.0,
                                evidence=reason, object_param=None, owner_lookup=None,
                                roles=[], allowed_membership=[])


def parse_result(text: str) -> ClassificationResult:
    try:
        return ClassificationResult.model_validate_json(text)
    except ValidationError:
        return manual_review("Invalid classification JSON or schema; manual review required")
