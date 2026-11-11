"""Frozen-dataset evaluation. Labels/answers never enter the model input."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from common.labels import Label
from common.schema import PolicyParams
from pipeline.classifier import classify, llm
from pipeline.classifier.schema import ClassificationResult
from pipeline.parsers.oas import Endpoint
from pipeline.parsers.erd import parse_erd


class Case(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str
    endpoint: Endpoint
    ddl: str
    controller_text: str | None = None
    expected_label: Label
    expected_params: PolicyParams | None = None
    rationale: str


class Dataset(BaseModel):
    model_config = ConfigDict(extra='forbid')
    name: str
    description: str
    cases: list[Case] = Field(min_length=1)


def load_dataset(path: Path) -> Dataset:
    dataset = Dataset.model_validate_json(path.read_text(encoding='utf-8'))
    if len({case.id for case in dataset.cases}) != len(dataset.cases):
        raise ValueError('Duplicate case ids')
    for case in dataset.cases:
        parse_erd(case.ddl)
    return dataset


def score(case: Case, result: ClassificationResult, elapsed: float) -> dict[str, Any]:
    params = PolicyParams(object_param=result.object_param, owner_lookup=result.owner_lookup,
                          roles=result.roles, allowed_membership=result.allowed_membership)
    return dict(id=case.id, method=case.endpoint.method, path=case.endpoint.path,
                expected=case.expected_label.value, actual=result.label.value,
                label_correct=case.expected_label == result.label,
                params_correct=params == case.expected_params if case.expected_params is not None else None,
                elapsed_seconds=elapsed, result=result.model_dump(mode='json'))


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [label.value for label in Label]
    matrix = {label: {other: 0 for other in labels} for label in labels}
    for row in rows:
        matrix[row['expected']][row['actual']] += 1
    total = len(rows)
    review = Label.MANUAL_REVIEW_REQUIRED.value
    automatic = [r for r in rows if r['actual'] != review]
    with_params = [r for r in rows if r['params_correct'] is not None]
    per_label = {}
    for label in labels:
        support = sum(matrix[label].values())
        predicted = sum(matrix[other][label] for other in labels)
        tp = matrix[label][label]
        precision = tp / predicted if predicted else 0.0
        recall = tp / support if support else 0.0
        per_label[label] = dict(support=support, predicted=predicted, precision=precision, recall=recall,
                                f1=2*precision*recall/(precision+recall) if precision+recall else 0.0)
    times = sorted(r['elapsed_seconds'] for r in rows)
    return dict(total=total, correct=sum(r['label_correct'] for r in rows),
        accuracy=sum(r['label_correct'] for r in rows)/total if total else None,
        manual_review_rate=sum(r['actual']==review for r in rows)/total if total else None,
        automatic_accuracy=sum(r['label_correct'] for r in automatic)/len(automatic) if automatic else None,
        full_policy_accuracy=sum(r['label_correct'] and r['params_correct'] for r in with_params)/len(with_params) if with_params else None,
        full_policy_support=len(with_params),
        provider_failures=sum(r['result']['evidence'].startswith('LLM unavailable:') for r in rows),
        mean_seconds=sum(times)/total if total else None,
        p50_seconds=times[math.ceil(total*0.5)-1] if total else None,
        p95_seconds=times[math.ceil(total*0.95)-1] if total else None,
        per_label=per_label, confusion_matrix=matrix)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    dataset = load_dataset(args.dataset)
    settings = llm.settings_from_env()
    if args.output.exists():
        parser.error('Output already exists; choose a new run file to preserve previous results')
    folder = Path(__file__).parent
    sources = [folder/'prompt.py', folder/'llm.py', folder/'schema.py', folder/'__init__.py',
               folder.parent/'parsers'/'oas.py', folder.parent/'parsers'/'erd.py', Path(__file__)]
    report: dict[str, Any] = dict(dataset=dataset.name,
        dataset_sha256=hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        source_sha256={str(p.relative_to(folder.parent.parent)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        provider=settings.provider, model=settings.model,
        started_at=datetime.now(timezone.utc).isoformat(), completed=False, rows=[])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def persist() -> None:
        report['summary'] = summarize(report['rows'])
        temporary = args.output.with_suffix(args.output.suffix+'.tmp')
        temporary.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        temporary.replace(args.output)
    persist()
    for index, case in enumerate(dataset.cases, 1):
        start = time.perf_counter()
        # Ground truth and rationale are deliberately excluded from this call.
        result = classify(case.endpoint, parse_erd(case.ddl), case.controller_text)
        row = score(case, result, time.perf_counter()-start)
        report['rows'].append(row)
        persist()
        print(f"{index}/{len(dataset.cases)} {case.id}: {row['actual']} "
              f"correct={row['label_correct']} seconds={row['elapsed_seconds']:.2f}",flush=True)
    report['completed'] = True
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    persist()
    print(json.dumps(report['summary'],ensure_ascii=True),flush=True)
    # Evaluation completion is not a model-quality pass threshold.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
