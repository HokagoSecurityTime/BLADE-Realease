"""Best-effort static authorization signals, never execution of uploaded code.

Keys are METHOD /path to distinguish GET and DELETE. Signals are evidence hints,
not a proof of authorization. Unsupported code yields an empty mapping + warning.
"""
import ast
import logging
import re
from typing import TypedDict


class ControllerSignals(TypedDict):
    has_auth_check: bool
    admin_bypass: bool
    tenant_check: bool
    owner_filter: bool
    raw_snippet: str


METHODS = {'get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'}


def _signals(text: str, raw: str) -> ControllerSignals:
    admin = bool(re.search(r'''(?:['"]admin['"]\s+in\s+[^\n]+roles|\bis_admin\b|\brole\s*={2,3}\s*['"]admin['"]|\broles\s*\.\s*includes\s*\(\s*['"]admin['"])''', text))
    tenant = bool(re.search(r'\b(?:tenant_id|org_id|organization_id)\s*={2,3}|={2,3}\s*[\w.]*\b(?:tenant_id|org_id|organization_id)\b', text))
    owner = bool(re.search(r'\.filter\s*\([^\n]*\b(?:user_id|owner_id)\s*==|\bWHERE\s+(?:\w+\.)?(?:user_id|owner_id)\b', text, re.I))
    auth = bool(re.search(r'\bcurrent_user\b|Depends\s*\(\s*get_current_user\b|\b(?:user\.id|owner_id)\s*={2,3}|HTTPException\s*\([^)]*\b403\b|\b(?:status|sendStatus)\s*\(\s*403\b|\b(?:UseGuards|ForbiddenException)\b', text))
    return dict(has_auth_check=auth or admin or tenant or owner, admin_bypass=admin,
                tenant_check=tenant, owner_filter=owner, raw_snippet=raw)


def _python(source: str) -> dict[str, ControllerSignals]:
    tree = ast.parse(source)
    result: dict[str, ControllerSignals] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue
            method = decorator.func.attr.lower()
            if method not in METHODS or not decorator.args:
                continue
            path = decorator.args[0]
            if not isinstance(path, ast.Constant) or not isinstance(path.value, str):
                continue
            # Exclude decorators (OAS descriptions are not auth checks) and docstrings.
            body = [statement for statement in node.body if not (
                isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str))]
            clean = ast.unparse(node.args) + '\n' + '\n'.join(ast.unparse(statement) for statement in body)
            raw = ast.get_source_segment(source, node) or ''
            result[f'{method.upper()} {path.value}'] = _signals(clean, raw)
    return result


def _normalize(path: str) -> str:
    return re.sub(r':([A-Za-z_]\w*)', r'{\1}', path)


def _express(text: str) -> tuple[str, ControllerSignals] | None:
    found = re.match(r'''\s*[\w.]+\.(get|post|put|patch|delete|head|options)\s*\(\s*(['"])(.*?)\2\s*,''', text, re.S)
    if not found:
        return None
    return f'{found[1].upper()} {_normalize(found[3])}', _signals(text[found.end():], text)


def _javascript(source: str) -> dict[str, ControllerSignals]:
    from tree_sitter import Language, Parser, Node
    import tree_sitter_typescript

    # TypeScript grammar also accepts Express JavaScript and Nest decorators.
    tree = Parser(Language(tree_sitter_typescript.language_typescript())).parse(source.encode('utf-8'))
    if tree.root_node.has_error:
        raise ValueError('JavaScript/TypeScript syntax could not be parsed')
    result: dict[str, ControllerSignals] = {}
    handlers: dict[str, str] = {}

    def collect(node: Node) -> None:
        if node.type in {'function_declaration', 'variable_declarator'}:
            name = node.child_by_field_name('name')
            value = node.child_by_field_name('value')
            if name and (node.type == 'function_declaration' or
                         (value and value.type in {'arrow_function', 'function_expression'})):
                handlers[name.text.decode('utf-8')] = node.text.decode('utf-8')
        for child in node.named_children:
            collect(child)

    collect(tree.root_node)

    def walk(node: Node) -> None:
        text = node.text.decode('utf-8')
        if node.type == 'call_expression':
            route = _express(text)
            if route:
                arguments = node.child_by_field_name('arguments')
                snippets = [text]
                if arguments:
                    for argument in arguments.named_children[1:]:
                        if argument.type == 'identifier':
                            snippet = handlers.get(argument.text.decode('utf-8'))
                            if snippet:
                                snippets.append(snippet)
                raw = '\n'.join(snippets)
                result[route[0]] = _signals(raw, raw)
        if node.type == 'class_declaration':
            prefix = re.search(r'''@Controller\s*\(\s*['"]([^'"]*)['"]\s*\)''', text)
            root = prefix[1].strip('/') if prefix else ''
            body = node.child_by_field_name('body')
            decorators: list[str] = []
            if body:
                for child in body.named_children:
                    value = child.text.decode('utf-8')
                    if child.type == 'decorator':
                        decorators.append(value)
                        continue
                    if child.type == 'method_definition':
                        value = '\n'.join(decorators) + '\n' + value
                        match = re.search(r'''@(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*['"]([^'"]*)['"]\s*\)''', value)
                        if match:
                            path = '/' + '/'.join(part for part in (root, match[2].strip('/')) if part)
                            result[f'{match[1].upper()} {_normalize(path)}'] = _signals(value, value)
                    decorators.clear()
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return result


def _fallback(source: str) -> dict[str, ControllerSignals]:
    result: dict[str, ControllerSignals] = {}
    starts = list(re.finditer(r'''\b[\w.]+\.(?:get|post|put|patch|delete|head|options)\s*\(\s*['"]''', source))
    for index, start in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(source)
        route = _express(source[start.start():end])
        if route:
            result[route[0]] = route[1]
    # Conservative Nest fallback; stop at the next route decorator to avoid
    # attributing one handler's admin branch to every route in the file.
    routes = list(re.finditer(r'''@(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*['"]([^'"]*)['"]\s*\)''', source))
    for index, route in enumerate(routes):
        prefixes = list(re.finditer(r'''@Controller\s*\(\s*['"]([^'"]*)['"]\s*\)''', source[:route.start()]))
        prefix = prefixes[-1][1].strip('/') if prefixes else ''
        end = routes[index + 1].start() if index + 1 < len(routes) else len(source)
        snippet = source[route.start():end]
        path = '/' + '/'.join(part for part in (prefix, route[2].strip('/')) if part)
        result[f'{route[1].upper()} {_normalize(path)}'] = _signals(snippet, snippet)
    return result


def parse_controller(source: str, language: str | None = None) -> dict[str, ControllerSignals]:
    """Parse text only; missing tree-sitter falls back to documented regex hints."""
    try:
        is_python = language in {'py', 'python'} or (language is None and bool(re.search(r'\b(?:async\s+)?def\s+\w+\s*\(', source)))
        if is_python:
            result = _python(source)
        else:
            try:
                result = _javascript(source)
            except ImportError:
                logging.warning('tree-sitter unavailable; using regex controller hints')
                result = _fallback(source)
        if not result:
            logging.warning('Unsupported controller framework or no recognized routes')
        return result
    except Exception as exc:
        logging.warning('Controller parsing failed (%s); no signals inferred', type(exc).__name__)
        return {}
