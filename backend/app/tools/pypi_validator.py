"""Package-registry oracle: detects hallucinated and suspicious (possibly squatted) imports.

A plain "does it exist on PyPI" check only catches names nobody has registered
yet. Once an attacker registers a hallucinated name the lookup succeeds, so we
also score registered packages on metadata: very new projects, projects with a
single release and no source link, and names that look like typos of popular
packages are flagged as suspicious.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from difflib import SequenceMatcher
from typing import Any, Dict, Iterable, List, Optional, Set

import requests

from app.core import config

# Import name -> PyPI distribution name, for the common cases where they differ.
IMPORT_TO_DIST = {
    "cv2": "opencv-python", "yaml": "PyYAML", "sklearn": "scikit-learn", "skimage": "scikit-image",
    "PIL": "Pillow", "bs4": "beautifulsoup4", "dateutil": "python-dateutil", "jwt": "PyJWT",
    "Crypto": "pycryptodome", "Cryptodome": "pycryptodomex", "dotenv": "python-dotenv",
    "attr": "attrs", "magic": "python-magic", "serial": "pyserial", "usb": "pyusb",
    "OpenSSL": "pyOpenSSL", "docx": "python-docx", "pptx": "python-pptx", "git": "GitPython",
    "zmq": "pyzmq", "MySQLdb": "mysqlclient", "Levenshtein": "python-Levenshtein", "fitz": "PyMuPDF",
    "telegram": "python-telegram-bot", "googleapiclient": "google-api-python-client",
    "jose": "python-jose", "multipart": "python-multipart", "slugify": "python-slugify",
    "socketio": "python-socketio", "engineio": "python-engineio", "ldap": "python-ldap",
    "nacl": "PyNaCl", "kafka": "kafka-python", "win32api": "pywin32", "win32con": "pywin32",
    "wx": "wxPython", "gi": "PyGObject", "Bio": "biopython", "pkg_resources": "setuptools",
    "dns": "dnspython", "sentry_sdk": "sentry-sdk",
    "faiss": "faiss-cpu", "tensorflow_hub": "tensorflow-hub", "markdown": "Markdown",
    "google.generativeai": "google-generativeai",
}

# Namespace packages / roots that are not themselves distributions.
NAMESPACE_ROOTS = {"google", "azure", "zope", "backports", "jaraco", "sphinxcontrib"}

POPULAR = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "pytest",
    "boto3", "botocore", "urllib3", "setuptools", "six", "certifi", "idna", "charset-normalizer",
    "python-dateutil", "pyyaml", "typing-extensions", "packaging", "cryptography", "pyjwt", "jinja2",
    "markupsafe", "werkzeug", "click", "itsdangerous", "scipy", "matplotlib", "scikit-learn", "pillow",
    "opencv-python", "beautifulsoup4", "lxml", "tensorflow", "torch", "transformers", "keras", "aiohttp",
    "httpx", "uvicorn", "gunicorn", "celery", "redis", "pymongo", "psycopg2", "psycopg2-binary",
    "mysqlclient", "paramiko", "selenium", "scrapy", "tqdm", "rich", "colorama", "pygments", "docutils",
    "sphinx", "black", "flake8", "pylint", "mypy", "isort", "coverage", "tox", "virtualenv", "pip",
    "wheel", "attrs", "toml", "tomli", "protobuf", "grpcio", "google-api-python-client", "openai",
    "anthropic", "langchain", "langgraph", "tiktoken", "nltk", "spacy", "gensim", "networkx", "sympy",
    "seaborn", "plotly", "dash", "streamlit", "bokeh", "xlrd", "openpyxl", "pyodbc", "pycryptodome",
    "bcrypt", "passlib", "python-dotenv", "marshmallow", "jsonschema", "simplejson", "ujson", "orjson",
    "websockets", "websocket-client", "pyserial", "pyzmq", "gitpython", "docker", "kubernetes",
    "ansible", "fabric", "invoke", "pexpect", "psutil", "pywin32", "pyopenssl", "pynacl", "dnspython",
    "python-multipart", "starlette", "sanic", "tornado", "twisted", "gevent", "eventlet", "greenlet",
    "arrow", "pendulum", "pytz", "tzdata", "babel", "faker", "factory-boy", "hypothesis", "mock",
    "responses", "httpretty", "freezegun", "boto", "s3transfer", "azure-storage-blob", "google-cloud-storage",
    "elasticsearch", "kafka-python", "pika", "sqlparse", "alembic", "peewee", "tortoise-orm",
    "pymysql", "aiofiles", "markdown", "defusedxml", "xmltodict", "pyparsing", "regex", "chardet",
    "html5lib", "bleach", "jmespath", "wrapt", "decorator", "cachetools", "tenacity", "backoff",
    "loguru", "structlog", "sentry-sdk", "prometheus-client", "pyarrow", "polars", "dask", "numba",
    "xgboost", "lightgbm", "catboost", "statsmodels", "joblib", "cython", "pybind11", "onnx",
    "onnxruntime", "faiss-cpu", "chromadb", "pinecone-client", "weaviate-client", "qdrant-client",
    "sentence-transformers", "huggingface-hub", "datasets", "accelerate", "peft", "bitsandbytes",
}

_CACHE: Dict[str, Dict[str, Any]] = {}


def _stdlib() -> Set[str]:
    names = set(getattr(sys, "stdlib_module_names", ()))
    names.add("__future__")
    return names


STDLIB = _stdlib()


def normalise(name: str) -> str:
    return name.lower().replace("_", "-").replace(".", "-")


def resolve_distribution(import_name: str) -> Optional[str]:
    """Map an import path ('yaml', 'google.generativeai', 'os.path') to a PyPI name, or None to skip."""
    if not import_name:
        return None
    if import_name in IMPORT_TO_DIST:
        return IMPORT_TO_DIST[import_name]
    root = import_name.split(".")[0]
    if root in STDLIB:
        return None
    if root in IMPORT_TO_DIST:
        return IMPORT_TO_DIST[root]
    if root in NAMESPACE_ROOTS:
        parts = import_name.split(".")
        return "-".join(parts[:2]) if len(parts) > 1 else None
    return root


def lookalike(dist: str) -> Optional[str]:
    """Return the popular package this name imitates, if it is a near-miss of one."""
    n = normalise(dist)
    if n in POPULAR:
        return None
    best, best_ratio = None, 0.0
    for p in POPULAR:
        if abs(len(p) - len(n)) > 3:
            continue
        r = SequenceMatcher(None, n, p).ratio()
        if r > best_ratio:
            best, best_ratio = p, r
    if best and best_ratio >= 0.86 and len(n) >= 4:
        return best
    # combosquatting: popular name plus a suffix/prefix, e.g. "requests-secure"
    for p in POPULAR:
        if len(p) >= 5 and n != p and (n.startswith(p + "-") or n.endswith("-" + p)):
            return p
    return None


def _fetch(dist: str) -> Dict[str, Any]:
    if dist in _CACHE:
        return _CACHE[dist]
    try:
        r = requests.get(f"https://pypi.org/pypi/{dist}/json", timeout=config.PYPI_TIMEOUT)
    except requests.RequestException:
        return {"reachable": False}
    if r.status_code == 404:
        data = {"reachable": True, "exists": False}
    elif r.status_code != 200:
        return {"reachable": False}
    else:
        js = r.json()
        info = js.get("info", {}) or {}
        uploads = []
        for files in (js.get("releases") or {}).values():
            for f in files or []:
                t = f.get("upload_time_iso_8601") or f.get("upload_time")
                if t:
                    uploads.append(t)
        first = min(uploads) if uploads else None
        urls = info.get("project_urls") or {}
        repo_link = any(("github.com" in (u or "") or "gitlab.com" in (u or "")) for u in list(urls.values()) + [info.get("home_page") or ""])
        data = {
            "reachable": True,
            "exists": True,
            "name": info.get("name"),
            "summary": (info.get("summary") or "")[:200],
            "releases": len(js.get("releases") or {}),
            "first_release": first,
            "has_repo_link": repo_link,
        }
    _CACHE[dist] = data
    return data


def _age_days(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


def assess(import_name: str, meta: Dict[str, Any], dist: str) -> Dict[str, Any]:
    reasons: List[str] = []
    look = lookalike(dist)
    if not meta.get("reachable"):
        return {"import": import_name, "package": dist, "status": "unknown",
                "reasons": ["PyPI unreachable; not verified"], "lookalike_of": look}
    if not meta.get("exists"):
        reasons.append("Not found on PyPI: likely a hallucinated package (slopsquatting target)")
        if look:
            reasons.append(f"Name resembles popular package '{look}'")
        return {"import": import_name, "package": dist, "status": "not_found", "reasons": reasons, "lookalike_of": look}

    age = _age_days(meta.get("first_release"))
    if look:
        reasons.append(f"Name closely resembles popular package '{look}' (possible typosquat)")
    if age is not None and age < config.NEW_PACKAGE_DAYS:
        reasons.append(f"First published only {age} days ago")
    if meta.get("releases", 0) <= 1 and not meta.get("has_repo_link"):
        reasons.append("Single release and no source repository link")
    status = "suspicious" if reasons else "ok"
    return {"import": import_name, "package": dist, "status": status, "reasons": reasons,
            "lookalike_of": look, "first_release": meta.get("first_release"),
            "releases": meta.get("releases"), "has_repo_link": meta.get("has_repo_link")}


def check_imports(imports: Iterable[str], local_modules: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """Full report for every third-party import."""
    local_modules = local_modules or set()
    report, seen = [], set()
    for imp in imports:
        if not imp or imp.split(".")[0] in local_modules:
            continue
        dist = resolve_distribution(imp)
        if not dist or normalise(dist) in seen:
            continue
        seen.add(normalise(dist))
        report.append(assess(imp, _fetch(dist), dist))
    return report


def verify_packages(packages: List[str]) -> List[Dict[str, Any]]:
    """Backwards-compatible API: only the problems, in the old alert shape."""
    alerts = []
    for r in check_imports(packages):
        if r["status"] in ("not_found", "suspicious"):
            alerts.append({
                "package": r["package"],
                "import": r["import"],
                "status": r["status"],
                "warning": "; ".join(r["reasons"]),
            })
    return alerts
