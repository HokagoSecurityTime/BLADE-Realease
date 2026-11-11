"""2-a label classifier: LoRA v4 served by Ollama (blade-qwen-lora-v4), prompt v3.0.1. Offline setup only.

The model returns only {label, confidence, rationale, evidence_fields}; policy parameters come from
pipeline.param_extractor (2-b). The user message reproduces the v3.0.1 training input format
(training/lora/prepare_lora_inputs.py test_record): "Return JSON.\\n" + endpoint payload, and the handler
excerpt appended to description when the controller has a handler for this route (oas_code condition).
"""

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re

from common.labels import Label
from pipeline.classifier import llm
from pipeline.parsers.controller import parse_controller
from pipeline.parsers.erd import TableInfo
from pipeline.parsers.oas import Endpoint

MODEL = 'blade-qwen-lora-v4'
PROMPT_VERSION = 'policy-label-v3.0.1'
PROMPT_SHA256 = 'd0913c27b5de185e7dd5734c111cb731f45e28ebca81fed787ff3914d02833ef'
PROMPT_PATH = Path(__file__).resolve().parents[2] / 'training' / 'data' / 'prompts' / 'policy_label_v3.0.1.md'
# Chosen on val_v4 only (training/lora/choose_threshold_v4.py --rule precision -> reports/eval/lora_v4_gguf/threshold_val_v4.json):
# val concrete precision 0.664 / manual 19.0% at 0.9 vs 0.642 / 16.3% at <=0.85. test_v30 was not used.
MIN_CONFIDENCE = 0.9
TIMEOUT_SECONDS = 600.0  # CPU inference of a ~3k-token prompt can take minutes
CODE_HEADER = '핸들러 원문(근거). 해당 엔드포인트의 인가 관련 코드 발췌이며 다른 검사가 더 있을 수 있다.\nFILE handler excerpt\n'
SCHEMA_PROVENANCE = 'Fields extracted from API response schema; not a verified database ERD'
_OWNER_COLUMN = re.compile(r'owner|user_id|author|created_by', re.I)
_TENANT_COLUMN = re.compile(r'tenant|org', re.I)


class LoraUnavailable(llm.LLMError):
    """Prompt file missing or changed; the caller falls back to the llm classifier."""


@dataclass
class LabelResult:
    label: Label
    confidence: float
    rationale: str
    evidence_fields: list[str] = field(default_factory=list)
    model_label: str | None = None  # label as returned by the model, before any manual conversion
    manual_reason: str | None = None  # why the result became manual_review_required here


def _prompt(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise LoraUnavailable(f'prompt v3.0.1 not readable at {path}') from exc
    if hashlib.sha256(data).hexdigest() != PROMPT_SHA256:
        raise LoraUnavailable('prompt v3.0.1 checksum mismatch')
    return data.decode('utf-8')


def related_tables(endpoint: Endpoint, erd: dict[str, TableInfo]) -> list[str]:
    """Tables named by a static path segment (orders, order), in path order."""
    segments = [s.lower() for s in endpoint.path.strip('/').split('/') if s and not s.startswith('{')]
    names = []
    for segment in segments:
        for name in erd:
            resource = name.rsplit('.', 1)[-1].lower()
            if name not in names and segment in {resource, resource.rstrip('s'), resource + 's'}:
                names.append(name)
    return names


def user_message(endpoint: Endpoint, erd: dict[str, TableInfo], controller_text: str | None) -> tuple[str, bool]:
    """Return (user message, has handler code)."""
    operation = endpoint.operation
    columns = [column for name in related_tables(endpoint, erd) for column in erd[name].columns]
    description = operation.get('description') or ''
    code = ''
    if controller_text:
        # Only this route's handler; another route's checks are not evidence for this one.
        code = (parse_controller(controller_text).get(f'{endpoint.method} {endpoint.path}') or {}).get('raw_snippet', '').strip()
    if code:
        description = (description + '\n' if description else '') + CODE_HEADER + code
    payload = dict(method=endpoint.method, path=endpoint.path, path_params=endpoint.path_params,
                   query_params=endpoint.query_params, summary=endpoint.summary or '', description=description,
                   security=operation.get('security', []), security_state=operation.get('security_state', 'unknown'),
                   schema_fields=operation.get('schema_fields', []), schema_provenance=SCHEMA_PROVENANCE,
                   owner_cols=[c for c in columns if _OWNER_COLUMN.search(c)],
                   tenant_cols=[c for c in columns if _TENANT_COLUMN.search(c)])
    return 'Return JSON.\n' + json.dumps(payload, ensure_ascii=False), bool(code)


def parse_output(text: str, min_confidence: float) -> LabelResult:
    """Same extraction as run_train.py parse(); anything outside the 6+1 labels becomes manual."""
    match = re.search(r'\{.*\}', text, re.S)
    try:
        data = json.loads(match.group(0)) if match else None
    except ValueError:
        data = None
    if not isinstance(data, dict) or data.get('label') not in {label.value for label in Label}:
        return LabelResult(Label.MANUAL_REVIEW_REQUIRED, 0.0, 'LoRA output is not valid label JSON',
                           model_label=data.get('label') if isinstance(data, dict) else None, manual_reason='parse')
    confidence = data.get('confidence')
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        return LabelResult(Label.MANUAL_REVIEW_REQUIRED, 0.0, 'LoRA output has no valid confidence',
                           model_label=data['label'], manual_reason='parse')
    rationale = data.get('rationale') if isinstance(data.get('rationale'), str) else ''
    fields = [f for f in data.get('evidence_fields') or [] if isinstance(f, str)] if isinstance(data.get('evidence_fields'), list) else []
    result = LabelResult(Label(data['label']), float(confidence), rationale, fields, model_label=data['label'])
    if result.label != Label.MANUAL_REVIEW_REQUIRED and result.confidence < min_confidence:
        result.label, result.manual_reason = Label.MANUAL_REVIEW_REQUIRED, 'confidence'
    return result


class LoraClassifier:
    """BLADE_LORA_MODEL (default blade-qwen-lora-v4), BLADE_LORA_MIN_CONFIDENCE, BLADE_LORA_PROMPT_PATH,
    BLADE_LORA_TIMEOUT; reuses the ollama provider and BLADE_OLLAMA_URL."""

    def __init__(self) -> None:
        self.model = os.getenv('BLADE_LORA_MODEL', MODEL).strip() or MODEL
        self.min_confidence = float(os.getenv('BLADE_LORA_MIN_CONFIDENCE', str(MIN_CONFIDENCE)))
        self.system = _prompt(Path(os.getenv('BLADE_LORA_PROMPT_PATH') or PROMPT_PATH))
        self.settings = llm.Settings('ollama', self.model,
                                     ollama_url=os.getenv('BLADE_OLLAMA_URL', 'http://127.0.0.1:11434').rstrip('/'),
                                     timeout=float(os.getenv('BLADE_LORA_TIMEOUT', str(TIMEOUT_SECONDS))))

    def classify(self, endpoint: Endpoint, erd: dict[str, TableInfo], controller_text: str | None = None) -> LabelResult:
        """Raises llm.LLMError when the model cannot be reached; unparsable output is a manual result."""
        user, _ = user_message(endpoint, erd, controller_text)
        # No JSON format constraint, as in training; a reply cut at num_predict is a parse failure, not an outage.
        text = llm.complete(self.system, user, settings=self.settings, json_format=False, allow_truncated=True)
        return parse_output(text, self.min_confidence)
