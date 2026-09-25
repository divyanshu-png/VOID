import requests
from typing import List, Dict, Any

PYPI_CACHE: Dict[str, bool] = {}

def verify_packages(packages: List[str]) -> List[Dict[str, Any]]:
    """
    Checks if extracted third-party packages exist on PyPI.
    Built-in standard library packages are ignored.
    """
    results: List[Dict[str, Any]] = []

    # Common standard libraries to skip checking
    stdlib = {
        "sys", "os", "ast", "math", "json", "time", "datetime", "typing",
        "subprocess", "difflib", "pathlib", "tempfile", "re", "collections",
        "random", "unittest", "logging"
    }

    for pkg in packages:
        root_pkg = pkg.split(".")[0]
        if root_pkg in stdlib:
            continue

        if root_pkg in PYPI_CACHE:
            exists = PYPI_CACHE[root_pkg]
        else:
            try:
                response = requests.get(
                    f"https://pypi.org/pypi/{root_pkg}/json",
                    timeout=3.0
                )
                exists = (response.status_code == 200)
            except requests.RequestException:
                exists = True  # Network fallback
            PYPI_CACHE[root_pkg] = exists

        if not exists:
            results.append({
                "package": root_pkg,
                "warning": "Suspected hallucinated or non-existent package (potential slopsquatting risk)."
            })

    return results