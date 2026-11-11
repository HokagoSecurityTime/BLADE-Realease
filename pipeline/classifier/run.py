"""Run the demo classification benchmark using a configured real provider."""

import argparse
import json
from pathlib import Path

from pipeline.classifier import classify, llm
from pipeline.parsers.erd import parse_erd
from pipeline.parsers.oas import parse_oas

# Evaluation ground truth only: never included in prompts or classification logic.
EXPECTED = {
    ("GET", "/public/health"): "public",
    ("GET", "/orders/{orderId}"): "owner_match",
    ("DELETE", "/orders/{orderId}"): "owner_match",
    ("GET", "/users/{userId}"): "owner_or_admin",
    ("GET", "/admin/reports"): "role_required",
    ("GET", "/orgs/{orgId}/docs"): "tenant_match",
    ("GET", "/premium/content"): "membership_required",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("oas", type=Path)
    parser.add_argument("erd", type=Path)
    parser.add_argument("--controller", type=Path)
    parser.add_argument("--output", type=Path, help="Optional JSON result file")
    args = parser.parse_args()
    endpoints = parse_oas(args.oas.read_text(encoding="utf-8"))
    erd = parse_erd(args.erd.read_text(encoding="utf-8"))
    controller = args.controller.read_text(encoding="utf-8") if args.controller else None
    try:
        settings = llm.settings_from_env()
    except llm.LLMConfigurationError as exc:
        print(f"Configuration error: {exc}", flush=True)
        return 2
    print(f"Provider: {settings.provider}; model: {settings.model}", flush=True)
    print("| Endpoint | Expected | Actual | Confidence | Match |", flush=True)
    print("| --- | --- | --- | --- | --- |", flush=True)
    results = []
    for endpoint in endpoints:
        result = classify(endpoint, erd, controller)
        expected = EXPECTED.get((endpoint.method, endpoint.path))
        match = result.label.value == expected
        results.append({"method": endpoint.method, "path": endpoint.path, "expected": expected,
                        "match": match, "result": result.model_dump(mode="json")})
        print(f"| {endpoint.method} {endpoint.path} | {expected or '-'} | {result.label.value} | "
              f"{result.confidence:.2f} | {'yes' if match else 'no'} |", flush=True)
    correct = sum(row["match"] for row in results)
    print(f"Correct: {correct}/{len(endpoints)}", flush=True)
    if args.output:
        args.output.write_text(json.dumps({"provider": settings.provider, "model": settings.model,
                                          "correct": correct, "total": len(endpoints), "results": results},
                                         ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    demo_complete = {(e.method, e.path) for e in endpoints} == set(EXPECTED) and len(endpoints) == 7
    return 0 if demo_complete and correct >= 6 else 1


if __name__ == "__main__":
    raise SystemExit(main())
