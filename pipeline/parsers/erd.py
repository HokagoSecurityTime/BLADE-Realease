"""Parse CREATE TABLE DDL as text only; never execute SQL.

Supports inline/table-level PKs and FKs, composite keys, quoted identifiers,
schema-qualified names, comments and nested type/default expressions.
Other statements (including ALTER TABLE) are rejected rather than ignored.
"""

from dataclasses import dataclass
import re


@dataclass
class ForeignKey:
    columns: list[str]
    ref_table: str
    ref_columns: list[str]


@dataclass
class TableInfo:
    pk: list[str]
    columns: list[str]
    owner_col: str | None
    tenant_col: str | None
    fks: list[ForeignKey]


_TOKEN = re.compile(
    r"\s+|--[^\n]*|/\*[\s\S]*?\*/|'(?:''|[^'])*'|"
    r'"(?:""|[^"])*"|`(?:``|[^`])*`|\[(?:\]\]|[^\]])*\]|'
    r"[A-Za-z_][\w$]*|\d+(?:\.\d+)?|[^\s]"
)
_OWNER = ("user_id", "owner_id", "created_by", "author_id")
_TENANT = ("tenant_id", "org_id", "organization_id", "company_id")
_USERS = {"users", "user"}
_TENANTS = {"orgs", "org", "tenants", "tenant", "organizations", "organization", "companies", "company"}


def _identifier(token: str) -> str:
    if token.startswith(('"', '`', '[')):
        end = ']' if token[0] == '[' else token[0]
        return token[1:-1].replace(end * 2, end)
    if not re.fullmatch(r"[A-Za-z_][\w$]*", token):
        raise ValueError(f"Expected SQL identifier, got {token!r}")
    return token


def _name(tokens: list[str], start: int) -> tuple[str, int]:
    parts = [_identifier(tokens[start])]
    end = start + 1
    while end < len(tokens) and tokens[end] == '.':
        parts.append(_identifier(tokens[end + 1]))
        end += 2
    return '.'.join(parts), end


def _group(tokens: list[str], start: int) -> tuple[list[str], int]:
    if start >= len(tokens) or tokens[start] != '(':
        raise ValueError("Expected parenthesized SQL group")
    depth = 1
    for end in range(start + 1, len(tokens)):
        if tokens[end] == '(':
            depth += 1
        elif tokens[end] == ')':
            depth -= 1
            if depth == 0:
                return tokens[start + 1:end], end + 1
    raise ValueError("Unclosed SQL group")


def _split(tokens: list[str]) -> list[list[str]]:
    result: list[list[str]] = []
    start = depth = 0
    for i, token in enumerate(tokens):
        if token == '(':
            depth += 1
        elif token == ')':
            depth -= 1
        elif token == ',' and depth == 0:
            result.append(tokens[start:i])
            start = i + 1
    result.append(tokens[start:])
    return result


def _key(tokens: list[str], start: int) -> tuple[list[str], int]:
    body, end = _group(tokens, start)
    parts = _split(body)
    if any(len(part) != 1 for part in parts):
        raise ValueError("Key columns must be plain identifiers")
    return [_identifier(part[0]) for part in parts], end


def _top_keywords(tokens: list[str]) -> list[str]:
    """Hide nested expressions so default/check text cannot become constraints."""
    depth = 0
    result: list[str] = []
    for token in tokens:
        if token == '(':
            depth += 1
        result.append(token.upper() if depth == 0 else "")
        if token == ')':
            depth -= 1
    return result


def parse_erd(ddl: str) -> dict[str, TableInfo]:
    """Return table metadata; pk/columns are ordered names and fks are records.

    Named column heuristics take priority over FK candidates in DDL order.
    A recognized tenant table uses its single-column PK as tenant_col.
    Composite tenant PKs are not guessed into a single-column policy.
    """
    tokens = [t for t in _TOKEN.findall(ddl)
              if not t.isspace() and not t.startswith(('--', '/*'))]
    tables: dict[str, TableInfo] = {}
    position = 0
    try:
        while position < len(tokens):
            if tokens[position] == ';':
                position += 1
                continue
            if [t.upper() for t in tokens[position:position + 2]] != ['CREATE', 'TABLE']:
                raise ValueError("Only CREATE TABLE statements are supported")
            position += 2
            if [t.upper() for t in tokens[position:position + 3]] == ['IF', 'NOT', 'EXISTS']:
                position += 3
            name, position = _name(tokens, position)
            body, position = _group(tokens, position)
            if name in tables:
                raise ValueError(f"Duplicate table: {name}")
            info = TableInfo([], [], None, None, [])
            for definition in _split(body):
                if not definition:
                    raise ValueError("Empty table definition")
                if definition[0].upper() == 'CONSTRAINT':
                    definition = definition[2:]
                upper = _top_keywords(definition)
                if upper[:2] == ['PRIMARY', 'KEY']:
                    info.pk, _ = _key(definition, 2)
                elif upper[:2] == ['FOREIGN', 'KEY']:
                    cols, end = _key(definition, 2)
                    if definition[end].upper() != 'REFERENCES':
                        raise ValueError("Foreign key needs REFERENCES")
                    target, end = _name(definition, end + 1)
                    refs, _ = _key(definition, end) if end < len(definition) and definition[end] == '(' else ([], end)
                    info.fks.append(ForeignKey(cols, target, refs))
                elif upper[0] in {'UNIQUE', 'CHECK'}:
                    continue
                else:
                    col = _identifier(definition[0])
                    info.columns.append(col)
                    if any(upper[i:i + 2] == ['PRIMARY', 'KEY'] for i in range(1, len(upper))):
                        info.pk.append(col)
                    if 'REFERENCES' in upper[1:]:
                        target, end = _name(definition, upper.index('REFERENCES', 1) + 1)
                        refs, _ = _key(definition, end) if end < len(definition) and definition[end] == '(' else ([], end)
                        info.fks.append(ForeignKey([col], target, refs))
            if any(col not in info.columns for col in info.pk + [c for fk in info.fks for c in fk.columns]):
                raise ValueError(f"Unknown key column in {name}")
            tables[name] = info
    except IndexError as exc:
        raise ValueError("Incomplete CREATE TABLE definition") from exc

    for name, info in tables.items():
        by_lower = {col.lower(): col for col in info.columns}
        for choices, targets, field in ((_OWNER, _USERS, 'owner_col'), (_TENANT, _TENANTS, 'tenant_col')):
            candidate = next((by_lower[c] for c in choices if c in by_lower), None)
            if candidate is None:
                candidate = next((fk.columns[0] for fk in info.fks
                                  if len(fk.columns) == 1 and fk.ref_table.rsplit('.', 1)[-1].lower() in targets), None)
            setattr(info, field, candidate)
        if name.rsplit('.', 1)[-1].lower() in _TENANTS and len(info.pk) == 1:
            info.tenant_col = info.pk[0]
    return tables
