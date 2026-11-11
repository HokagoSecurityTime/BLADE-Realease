"""Load immutable versioned prompt data; no code execution or external I/O."""
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any


def prompt_path(version: str | None = None) -> Path:
    version = version or os.getenv('BLADE_PROMPT_VERSION', 'v2.0')
    if not re.fullmatch(r'v\d+\.\d+', version):
        raise ValueError('Invalid prompt version')
    return Path(__file__).resolve().parents[2] / 'prompts' / (version + '.md')


def prompt_bundle(version: str | None = None) -> dict[str, Any]:
    path = prompt_path(version)
    text = path.read_text(encoding='utf-8')
    expected = re.search(r'^SHA-256: ([a-f0-9]{64})$', text, re.MULTILINE)
    match = re.search(r'```json\n(.*?)\n```', text, re.DOTALL)
    if expected is None or match is None or hashlib.sha256(match.group(1).encode('utf-8')).hexdigest() != expected.group(1):
        raise ValueError('Prompt snapshot checksum mismatch')
    result = json.loads(match.group(1))
    if result['version'] != path.stem:
        raise ValueError('Prompt version mismatch')
    return result
