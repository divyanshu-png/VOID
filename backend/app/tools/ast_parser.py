import ast
from typing import Dict, Any, List

def parse_code_structure(code: str) -> Dict[str, Any]:
    """
    Deterministically parses source code to extract structural elements,
    symbols, function signatures, and imports.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return {
            "valid_syntax": False,
            "syntax_error": f"Line {exc.lineno}: {exc.msg}",
            "imports": [],
            "functions": [],
            "classes": []
        }

    imports: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module)

    functions = [
        {
            "name": node.name,
            "args": [arg.arg for arg in node.args.args],
            "lineno": node.lineno
        }
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
    ]

    classes = [
        {"name": node.name, "lineno": node.lineno}
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
    ]

    return {
        "valid_syntax": True,
        "syntax_error": None,
        "imports": list(set(imports)),
        "functions": functions,
        "classes": classes
    }