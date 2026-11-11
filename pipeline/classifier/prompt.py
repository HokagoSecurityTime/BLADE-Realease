"""Single-endpoint classification prompts; no training or retrieval stage."""

from dataclasses import asdict
from pipeline.classifier.prompt_store import prompt_bundle
import json
import re
from common.features import enabled
from common.schema import EvidenceRef
from pipeline.parsers.controller import parse_controller

from pipeline.parsers.erd import TableInfo
from pipeline.parsers.oas import Endpoint

SYSTEM_PROMPT = prompt_bundle()["system"]


def build_user_prompt(endpoint: Endpoint, erd: dict[str, TableInfo], controller_text: str | None = None,
                      evidence_refs: list[EvidenceRef] | None = None, *, security_context: dict | None = None) -> str:
    # The caller supplies the relevant ERD context. Preserve it, including FK targets.
    bindings = []
    segments = endpoint.path.strip('/').split('/')
    for name, table in erd.items():
        resource = name.rsplit('.', 1)[-1]
        if resource not in segments or len(table.pk) != 1:
            continue
        for parameter in endpoint.path_params + endpoint.query_params:
            if parameter.lower().replace('_', '') == resource.rstrip('s').lower() + 'id':
                bindings.append({'object_param': parameter, 'table': name, 'id_col': table.pk[0],
                                 'owner_col': table.owner_col, 'tenant_col': table.tenant_col})
    values = {"endpoint": asdict(endpoint), "tables": {name: asdict(table) for name, table in erd.items()},
              "object_bindings": bindings, "controller_text": controller_text,
              "security_context": security_context or {"status": "unknown", "requirements": None, "scopes": []}}
    payload = {key: values[value[1:]] if isinstance(value, str) and value.startswith("$") else value
               for key, value in prompt_bundle()["user_template"].items()}
    if enabled('BLADE_CONTROLLER_ENABLED') and controller_text:
        signals = parse_controller(controller_text)
        current = signals.get(f'{endpoint.method} {endpoint.path}', {})
        payload['Controller 신호'] = current
        # A missing handler is not permission to use other routes' auth checks.
        payload['controller_text'] = current.get('raw_snippet')
        for binding in bindings:
            parameter = re.escape(binding['object_param'])
            identity = r'(?:current_user|user)\.(?:id|sub)'
            if current and binding['owner_col'] is None and re.search(
                rf'\b{identity}\s*(?:==|!=)\s*{parameter}\b|\b{parameter}\s*(?:==|!=)\s*{identity}\b',
                current['raw_snippet'],
            ):
                # A direct caller-id vs route-id comparison identifies the lookup
                # key itself as the ownership column, even without a users FK.
                binding['owner_col'] = binding['id_col']
                binding['owner_binding_basis'] = 'controller compares caller identity directly with this object parameter'
    if enabled('BLADE_RAG_ENABLED') and evidence_refs:
        payload['참고 근거'] = [ref.model_dump() for ref in evidence_refs]
    return json.dumps(payload, ensure_ascii=False)


def system_prompt(*, rag: bool = False) -> str:
    result = _controller_system_prompt()
    if rag and enabled('BLADE_RAG_ENABLED'):
        result += prompt_bundle()["rag_extension"]
    return result


def _controller_system_prompt() -> str:
    if enabled('BLADE_CONTROLLER_ENABLED'):
        return prompt_bundle()["system"] + prompt_bundle()["controller_extension"]
    return prompt_bundle()["system"]
