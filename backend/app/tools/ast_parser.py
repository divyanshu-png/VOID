"""Deterministic structure extraction with Python's ast module."""
from __future__ import annotations

import ast
from typing import Any, Dict, List, Optional


def parse_code_structure(code: str) -> Dict[str, Any]:
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {"valid_syntax": False, "syntax_error": f"Line {exc.lineno}: {exc.msg}",
                "imports": [], "functions": [], "classes": []}

    imports: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imports.append(node.module)  # relative imports (level > 0) are local

    functions = [
        {"name": n.name, "args": [a.arg for a in n.args.args], "lineno": n.lineno,
         "end_lineno": getattr(n, "end_lineno", n.lineno), "is_async": isinstance(n, ast.AsyncFunctionDef)}
        for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    classes = [{"name": n.name, "lineno": n.lineno, "end_lineno": getattr(n, "end_lineno", n.lineno)}
               for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
    return {"valid_syntax": True, "syntax_error": None, "imports": sorted(set(imports)),
            "functions": functions, "classes": classes}


def _header(tree: ast.Module, lines: List[str]) -> List[str]:
    """Module-level imports and simple constant assignments, kept as context for a snippet."""
    out = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)) and not getattr(node, "level", 0):
            out.extend(lines[node.lineno - 1: node.end_lineno])
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            out.extend(lines[node.lineno - 1: node.end_lineno])
    return out


def extract_enclosing(code: str, line: int) -> Optional[Dict[str, Any]]:
    """Return the smallest top-level function / method / class around `line`, plus import context.

    The snippet is self-contained enough to audit and test: module imports are
    prepended, and methods are returned with their class so `self` makes sense.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None
    lines = code.splitlines()
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            end = getattr(node, "end_lineno", node.lineno)
            if start <= line <= end and (best is None or (end - start) < (best[2] - best[1])):
                best = (node, start, end)
    if best is None:
        return None
    node, start, end = best
    # A method alone cannot run; widen to the enclosing class when small enough.
    for parent in tree.body:
        if isinstance(parent, ast.ClassDef) and parent.lineno <= start and end <= parent.end_lineno:
            if parent.end_lineno - parent.lineno <= 120:
                node, start, end = parent, parent.lineno, parent.end_lineno
            break
    header = _header(tree, lines)
    body = lines[start - 1: end]
    snippet = "\n".join(header + ([""] if header else []) + body) + "\n"
    return {
        "name": getattr(node, "name", "?"),
        "kind": type(node).__name__,
        "start_line": start,
        "end_line": end,
        "header_lines": len(header) + (1 if header else 0),
        "snippet": snippet,
        "original_block": "\n".join(body) + "\n",
    }


def merge_patch_into_file(file_code: str, info: Dict[str, Any], patched_snippet: str) -> str:
    """Put a patched snippet back into the full file.

    The block named `info['name']` is taken from the patched snippet and replaces
    the original lines; imports the patch added are inserted after the file's
    last top-level import. Falls back to the original file if the patch has no
    such block.
    """
    try:
        ptree = ast.parse(patched_snippet)
        ftree = ast.parse(file_code)
    except SyntaxError:
        return file_code
    plines = patched_snippet.splitlines()

    def lines_of(node) -> List[str]:
        start = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
        return plines[start - 1: node.end_lineno]

    target = next((n for n in ptree.body if getattr(n, "name", None) == info["name"]), None)
    if target is None:
        return file_code
    block = lines_of(target)

    flines = file_code.splitlines()
    existing = {ast.get_source_segment(file_code, n) for n in ftree.body if isinstance(n, (ast.Import, ast.ImportFrom))}
    new_imports = [ast.get_source_segment(patched_snippet, n) for n in ptree.body
                   if isinstance(n, (ast.Import, ast.ImportFrom))
                   and ast.get_source_segment(patched_snippet, n) not in existing]

    # Module-level definitions the patched block needs but the file lacks: constants
    # (`logger = ...`), helper functions and classes, followed transitively, so a
    # helper's own constants come along too.
    def defines(n) -> List[str]:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return [n.name]
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if isinstance(n, ast.AnnAssign) else []
        return [t.id for t in targets if isinstance(t, ast.Name)]

    defined = {name for n in ftree.body for name in defines(n)}
    helpers = {name: n for n in ptree.body if n is not target for name in defines(n)}
    needed, seen = set(), set()
    todo = [x.id for x in ast.walk(target) if isinstance(x, ast.Name)]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        node = helpers.get(name)
        if node is not None and name not in defined:
            needed.add(id(node))
            todo += [x.id for x in ast.walk(node) if isinstance(x, ast.Name)]
    carried = [lines_of(n) for n in ptree.body if id(n) in needed]

    out = flines[: info["start_line"] - 1] + block + flines[info["end_line"]:]
    insert = list(new_imports)
    for lines in carried:
        insert += [""] + lines
    if carried:
        insert.append("")
    if insert:
        last_import = 0
        for n in ftree.body:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                last_import = n.end_lineno
        out = out[:last_import] + insert + out[last_import:]
    return "\n".join(out) + ("\n" if file_code.endswith("\n") else "")
