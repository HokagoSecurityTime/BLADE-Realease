"""Deterministic offline corpus loaders. Uploaded code is never executed."""
import ast
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

from common.schema import Policy, PolicyStatus, policy_to_yaml


@dataclass(frozen=True)
class Chunk:
    kind: str
    ref: str
    text: str

    @property
    def id(self) -> str:
        return hashlib.sha256(f'{self.kind}\0{self.ref}\0{self.text}'.encode()).hexdigest()


def load_code(source: str, ref: str) -> list[Chunk]:
    """Functions/methods are chunks; ORM classes without methods remain intact."""
    if ref.endswith('.py'):
        try:
            tree = ast.parse(source)
            lines = source.splitlines()
            chunks = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    if any(isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for child in node.body):
                        continue
                    start = min([node.lineno] + [d.lineno for d in node.decorator_list])
                    text = '\n'.join(lines[start-1:node.end_lineno])
                    chunks.append(Chunk('code', f'{ref}#L{start}:{node.name}', text))
            return chunks or [Chunk('code', ref, source)]
        except SyntaxError:
            return [Chunk('code', ref, source)]
    if ref.endswith(('.js', '.ts', '.tsx', '.jsx')):
        try:
            from tree_sitter import Language, Parser, Node
            import tree_sitter_typescript
            tree = Parser(Language(tree_sitter_typescript.language_typescript())).parse(source.encode())
            chunks = []
            def walk(node: Node) -> None:
                if node.type in {'function_declaration', 'method_definition', 'arrow_function', 'function_expression'}:
                    chunks.append(Chunk('code', f'{ref}#L{node.start_point.row + 1}', node.text.decode()))
                    return
                for child in node.named_children:
                    walk(child)
            walk(tree.root_node)
            return chunks or [Chunk('code', ref, source)]
        except ImportError:
            from pipeline.parsers.controller import parse_controller
            signals = parse_controller(source)
            return [Chunk('code', f'{ref}#{route}', row['raw_snippet']) for route, row in signals.items()] or [Chunk('code', ref, source)]
    return []


def load_zip(data: bytes) -> list[Chunk]:
    chunks: list[Chunk] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > 500 or sum(m.file_size for m in members) > 20_000_000:
                raise ValueError('Code archive is too large')
            for member in members:
                path = PurePosixPath(member.filename.replace('\\', '/'))
                if path.is_absolute() or '..' in path.parts or ':' in member.filename:
                    raise ValueError('Unsafe archive member name')
                if member.is_dir() or path.suffix not in {'.py', '.js', '.jsx', '.ts', '.tsx'}:
                    continue
                if member.file_size > 1_000_000:
                    raise ValueError('Source file is too large')
                chunks.extend(load_code(archive.read(member).decode('utf-8-sig'), str(path)))
    except (zipfile.BadZipFile, UnicodeError, RuntimeError) as exc:
        raise ValueError('Invalid UTF-8 code archive') from exc
    return chunks


def load_idioms(directory: Path | None = None) -> list[Chunk]:
    directory = directory or Path(__file__).parents[1]/'idioms'
    chunks: list[Chunk] = []
    for path in sorted(directory.glob('*.md')):
        text = path.read_text(encoding='utf-8')
        for index, section in enumerate(re.split(r'(?m)(?=^#{1,6} )', text)):
            if section.strip():
                chunks.append(Chunk('idiom', f'idioms/{path.name}#{index}', section.strip()))
    return chunks


def load_policies(policies: list[Policy]) -> list[Chunk]:
    return [Chunk('policy', f'policies/{p.id}@v{p.version}', policy_to_yaml(p))
            for p in policies if p.status == PolicyStatus.ACTIVE]


def load_cves(path: Path) -> list[Chunk]:
    if not path.exists():
        return []
    chunks = []
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', row.get('cve_id', '')) or not isinstance(row.get('summary'), str):
            raise ValueError('Invalid CVE corpus record')
        chunks.append(Chunk('cve', row['cve_id'], json.dumps(row, ensure_ascii=False)))
    return chunks
