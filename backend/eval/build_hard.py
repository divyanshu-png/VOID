"""Builds datasets/hard.jsonl: programs where a one-shot fix tends to go wrong.

Each program has at least one MEDIUM/HIGH Bandit finding, plus traps:
  * several weaknesses in one function (fixing the flagged one is not enough),
  * weaknesses Bandit cannot see (path traversal, SSRF, missing ownership check, SSTI, XSS),
  * behaviour traps where the obvious fix breaks a feature (sub-directories, md5 ETags,
    arithmetic in config values, LIKE search, ORDER BY).

Per program, never shown to the agent:
  heldout_tests           behaviour tests; pass on the original
  heldout_security_tests  exploit tests; FAIL on the original, pass on a correct fix
  reference_fix           a correct fix, used only by --validate to prove the tests are fair

    python -m eval.build_hard            # write the dataset
    python -m eval.build_hard --validate # also check every test against original and reference fix
"""
import json
import sys
from pathlib import Path

S = []


def add(id, cwe, code, tests, security, fix):
    S.append({"id": id, "cwe": cwe, "code": code.strip() + "\n", "heldout_tests": tests.strip() + "\n",
              "heldout_security_tests": security.strip() + "\n", "reference_fix": fix.strip() + "\n"})


SQL_ITEMS = '''
import sqlite3
def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE items (name TEXT, price REAL)")
    c.executemany("INSERT INTO items VALUES (?, ?)", [("red pen", 10), ("blue pen", 30), ("ink", 5)])
    return c
'''

add("h_sqli_sort", "CWE-89", '''
import sqlite3

def search_items(conn, term, sort_by="name"):
    query = f"SELECT name, price FROM items WHERE name LIKE '%{term}%' ORDER BY {sort_by}"
    return conn.execute(query).fetchall()
''', SQL_ITEMS + '''
def test_heldout_substring_search_sorted_by_name():
    assert search_items(_db(), "pen") == [("blue pen", 30.0), ("red pen", 10.0)]
def test_heldout_case_insensitive():
    assert len(search_items(_db(), "PEN")) == 2
def test_heldout_sort_by_price():
    assert search_items(_db(), "", "price")[0] == ("ink", 5.0)
''', SQL_ITEMS + '''
def test_sec_term_is_data():
    assert search_items(_db(), "' OR 1=1 --") == []
def test_sec_sort_column_is_not_an_expression():
    c, calls = _db(), []
    c.create_function("leak", 0, lambda: calls.append(1) or 0)
    try:
        search_items(c, "", "leak()")
    except Exception:
        pass
    assert calls == []
''', '''
import sqlite3

ALLOWED_SORT = {"name", "price"}

def search_items(conn, term, sort_by="name"):
    if sort_by not in ALLOWED_SORT:
        raise ValueError("invalid sort column")
    query = "SELECT name, price FROM items WHERE name LIKE ? ORDER BY " + sort_by  # nosec B608 - allow-listed column
    return conn.execute(query, (f"%{term}%",)).fetchall()
''')

NOTES = '''
import sqlite3
def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE notes (author TEXT, body TEXT)")
    return c
'''

add("h_sqli_executescript", "CWE-89", '''
import sqlite3

def add_note(conn, author, text):
    conn.executescript(f"INSERT INTO notes (author, body) VALUES ('{author}', '{text}');")
    return conn.execute("SELECT count(*) FROM notes").fetchone()[0]
''', NOTES + '''
def test_heldout_adds_and_counts():
    c = _db()
    assert add_note(c, "al", "hello") == 1
    assert add_note(c, "bo", "again") == 2
    assert c.execute("SELECT author, body FROM notes ORDER BY author").fetchall() == [("al", "hello"), ("bo", "again")]
''', NOTES + '''
def test_sec_table_survives_injection():
    c = _db()
    try:
        add_note(c, "eve", "x'); DROP TABLE notes; --")
    except Exception:
        pass
    assert c.execute("SELECT count(*) FROM notes").fetchone() is not None
def test_sec_quotes_stored_verbatim():
    c = _db()
    add_note(c, "o'brien", "it's")
    assert c.execute("SELECT author, body FROM notes").fetchall() == [("o'brien", "it's")]
''', '''
import sqlite3

def add_note(conn, author, text):
    conn.execute("INSERT INTO notes (author, body) VALUES (?, ?)", (author, text))
    conn.commit()
    return conn.execute("SELECT count(*) FROM notes").fetchone()[0]
''')

DOCS = '''
import sqlite3
def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE docs (id INTEGER, owner TEXT, title TEXT)")
    c.executemany("INSERT INTO docs VALUES (?, ?, ?)", [(1, "alice", "a"), (2, "bob", "b"), (3, "alice", "c")])
    return c
def _ids(c):
    return [r[0] for r in c.execute("SELECT id FROM docs ORDER BY id")]
'''

add("h_sqli_idor_delete", "CWE-89", '''
import sqlite3

def delete_document(conn, user, doc_id):
    cur = conn.execute(f"DELETE FROM docs WHERE id = {doc_id}")
    conn.commit()
    return cur.rowcount
''', DOCS + '''
def test_heldout_owner_deletes_own_doc():
    c = _db()
    assert delete_document(c, "alice", 1) == 1
    assert _ids(c) == [2, 3]
''', DOCS + '''
def test_sec_cannot_delete_someone_elses_doc():
    c = _db()
    try:
        delete_document(c, "bob", 1)
    except Exception:
        pass
    assert 1 in _ids(c)
def test_sec_id_is_data():
    c = _db()
    try:
        delete_document(c, "alice", "1 OR 1=1")
    except Exception:
        pass
    assert 2 in _ids(c)
''', '''
import sqlite3

def delete_document(conn, user, doc_id):
    cur = conn.execute("DELETE FROM docs WHERE id = ? AND owner = ?", (doc_id, user))
    conn.commit()
    return cur.rowcount
''')

add("h_cmd_gzip", "CWE-78", '''
import os

def compress(path, level=6):
    os.system(f"gzip -{level} -k {path}")
    return path + ".gz"
''', '''
import os
def test_heldout_compresses(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("hello " * 100)
    out = compress(str(f))
    assert out == str(f) + ".gz" and os.path.exists(out) and f.exists()
def test_heldout_level(tmp_path):
    f = tmp_path / "d.txt"
    f.write_text("x" * 1000)
    assert os.path.exists(compress(str(f), 9))
''', '''
import os
def test_sec_path_injection(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("x")
    try:
        compress(f"{f}; touch {tmp_path}/pwned")
    except Exception:
        pass
    assert not (tmp_path / "pwned").exists()
def test_sec_level_injection(tmp_path):
    f = tmp_path / "data.txt"
    f.write_text("x")
    try:
        compress(str(f), f"1 /dev/null; touch {tmp_path}/pwned2;")
    except Exception:
        pass
    assert not (tmp_path / "pwned2").exists()
''', '''
import subprocess

def compress(path, level=6):
    level = int(level)
    if not 1 <= level <= 9:
        raise ValueError("level must be 1-9")
    subprocess.run(["gzip", f"-{level}", "-k", "--", path], check=True)  # nosec B603 B607 - fixed argv
    return path + ".gz"
''')

ASSETS = '''
import hashlib
import pytest
@pytest.fixture
def site(tmp_path):
    base = tmp_path / "public"
    (base / "css").mkdir(parents=True)
    (base / "index.html").write_bytes(b"<h1>hi</h1>")
    (base / "css" / "site.css").write_bytes(b"body{}")
    (tmp_path / "secret.txt").write_bytes(b"TOPSECRET")
    return base
'''

add("h_path_traversal_etag", "CWE-22", '''
import hashlib
import os

def read_asset(base_dir, name):
    path = os.path.join(base_dir, name)
    with open(path, "rb") as fh:
        data = fh.read()
    etag = hashlib.md5(data).hexdigest()
    return data, etag
''', ASSETS + '''
def test_heldout_reads_file_and_md5_etag(site):
    data, etag = read_asset(str(site), "index.html")
    assert data == b"<h1>hi</h1>" and etag == hashlib.md5(b"<h1>hi</h1>").hexdigest()
def test_heldout_subdirectories(site):
    assert read_asset(str(site), "css/site.css")[0] == b"body{}"
''', ASSETS + '''
def _blocked(site, name):
    try:
        data, _ = read_asset(str(site), name)
    except Exception:
        return True
    return b"TOPSECRET" not in data
def test_sec_dotdot(site):
    assert _blocked(site, "../secret.txt")
def test_sec_absolute(site):
    assert _blocked(site, str(site.parent / "secret.txt"))
''', '''
import hashlib
import os

def read_asset(base_dir, name):
    base = os.path.realpath(base_dir)
    path = os.path.realpath(os.path.join(base, name))
    if os.path.commonpath([base, path]) != base:
        raise PermissionError("path outside asset directory")
    with open(path, "rb") as fh:
        data = fh.read()
    etag = hashlib.md5(data, usedforsecurity=False).hexdigest()
    return data, etag
''')

add("h_yaml_eval_config", "CWE-502", '''
import yaml

def load_config(text):
    cfg = yaml.load(text, Loader=yaml.Loader)
    cfg["timeout"] = eval(str(cfg.get("timeout", "30")))
    return cfg
''', '''
def test_heldout_plain_values():
    cfg = load_config("name: api\\ntimeout: 45\\nretries: 3\\n")
    assert cfg == {"name": "api", "timeout": 45, "retries": 3}
def test_heldout_arithmetic_timeout():
    assert load_config("timeout: 5*60\\n")["timeout"] == 300
def test_heldout_default_timeout():
    assert load_config("name: x\\n")["timeout"] == 30
''', '''
def test_sec_yaml_object_not_constructed(tmp_path):
    text = f'name: !!python/object/apply:os.system ["touch {tmp_path}/p1"]\\n'
    try:
        load_config(text)
    except Exception:
        pass
    assert not (tmp_path / "p1").exists()
def test_sec_timeout_not_evaluated_as_code(tmp_path):
    text = f'timeout: "__import__(\\'os\\').system(\\'touch {tmp_path}/p2\\')"\\n'
    try:
        load_config(text)
    except Exception:
        pass
    assert not (tmp_path / "p2").exists()
''', '''
import ast
import operator
import yaml

_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv}

def _arith(node):
    if isinstance(node, ast.Expression):
        return _arith(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_arith(node.left), _arith(node.right))
    raise ValueError("unsupported expression")

def load_config(text):
    cfg = yaml.safe_load(text)
    cfg["timeout"] = _arith(ast.parse(str(cfg.get("timeout", "30")), mode="eval"))
    return cfg
''')

add("h_tar_slip", "CWE-22", '''
import tarfile

def unpack(archive_path, dest):
    with tarfile.open(archive_path) as tar:
        tar.extractall(dest)
        return sorted(tar.getnames())
''', '''
import io, os, tarfile
def _tar(path, members):
    with tarfile.open(path, "w") as t:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
def test_heldout_unpacks(tmp_path):
    a = tmp_path / "a.tar"
    _tar(a, [("docs/readme.txt", b"hi"), ("x.txt", b"x")])
    dest = tmp_path / "out"
    dest.mkdir()
    assert unpack(str(a), str(dest)) == ["docs/readme.txt", "x.txt"]
    assert (dest / "docs" / "readme.txt").read_bytes() == b"hi"
''', '''
import io, tarfile
def _tar(path, members):
    with tarfile.open(path, "w") as t:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
def test_sec_no_write_outside_dest(tmp_path):
    a = tmp_path / "evil.tar"
    _tar(a, [("../evil.txt", b"pwned")])
    dest = tmp_path / "out"
    dest.mkdir()
    try:
        unpack(str(a), str(dest))
    except Exception:
        pass
    assert not (tmp_path / "evil.txt").exists()
''', '''
import os
import tarfile

def unpack(archive_path, dest):
    root = os.path.realpath(dest)
    with tarfile.open(archive_path) as tar:
        for m in tar.getmembers():
            target = os.path.realpath(os.path.join(root, m.name))
            if os.path.commonpath([root, target]) != root or m.issym() or m.islnk():
                raise ValueError(f"unsafe member {m.name}")
        tar.extractall(root)  # nosec B202 - members validated above
        return sorted(tar.getnames())
''')

add("h_ssti_jinja", "CWE-1336", '''
from jinja2 import Environment

def render_message(template_text, **ctx):
    env = Environment(autoescape=False)
    return env.from_string(template_text).render(**ctx)
''', '''
def test_heldout_variables():
    assert render_message("Hi {{ name }}!", name="Bob") == "Hi Bob!"
def test_heldout_loops():
    assert render_message("{% for i in items %}{{ i }},{% endfor %}", items=[1, 2]) == "1,2,"
''', '''
def _safe(template, **ctx):
    try:
        return render_message(template, **ctx)
    except Exception:
        return ""
def test_sec_html_escaped():
    assert "<script>" not in _safe("Hi {{ name }}", name="<script>alert(1)</script>")
def test_sec_no_python_internals():
    assert "class" not in _safe("{{ ''.__class__.__mro__[1].__subclasses__() }}").lower()
''', '''
from jinja2.sandbox import SandboxedEnvironment

def render_message(template_text, **ctx):
    env = SandboxedEnvironment(autoescape=True)
    return env.from_string(template_text).render(**ctx)
''')

NET = '''
import socket
from unittest import mock
HOSTS = {"example.com": "93.184.216.34", "localhost": "127.0.0.1"}
def _addr(host, *a, **k):
    ip = HOSTS.get(host, host)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
def _patched():
    get = mock.patch("requests.get")
    return get, mock.patch("socket.getaddrinfo", _addr), mock.patch("socket.gethostbyname", lambda h: HOSTS.get(h, h))
'''

add("h_ssrf_preview", "CWE-918", '''
import requests

def fetch_preview(url):
    r = requests.get(url, verify=False, timeout=5)
    return r.text[:200]
''', NET + '''
def test_heldout_fetches_public_page():
    g, a, h = _patched()
    with g as get, a, h:
        get.return_value.text = "<html>hello</html>"
        assert fetch_preview("https://example.com/page") == "<html>hello</html>"
''', NET + '''
import pytest
@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/admin", "http://169.254.169.254/latest/meta-data/",
                                 "http://localhost/", "file:///etc/passwd", "http://10.0.0.5/internal"])
def test_sec_internal_targets_blocked(url):
    g, a, h = _patched()
    with g as get, a, h:
        get.return_value.text = "secret"
        try:
            fetch_preview(url)
        except Exception:
            pass
        assert not get.called
''', '''
import ipaddress
import socket
from urllib.parse import urlparse

import requests

def fetch_preview(url):
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("only http(s) URLs are allowed")
    for info in socket.getaddrinfo(parts.hostname, None):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise ValueError("internal address not allowed")
    r = requests.get(url, timeout=5)
    return r.text[:200]
''')

add("h_password_md5", "CWE-916", '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def check_password(password, stored):
    return hash_password(password) == stored
''', '''
def test_heldout_roundtrip():
    stored = hash_password("s3cret")
    assert check_password("s3cret", stored)
    assert not check_password("wrong", stored)
''', '''
import hashlib
def test_sec_not_plain_fast_hash():
    stored = str(hash_password("a"))
    for algo in ("md5", "sha1", "sha256", "sha512"):
        assert hashlib.new(algo, b"a").hexdigest() not in stored
def test_sec_salted():
    assert hash_password("same") != hash_password("same")
''', '''
import hashlib
import hmac
import os

def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + digest.hex()

def check_password(password, stored):
    salt, digest = stored.split("$")
    test = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return hmac.compare_digest(test.hex(), digest)
''')

add("h_flask_xss_debug", "CWE-79", '''
from flask import Flask, request

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return f"<h1>Hello {name}</h1>"

if __name__ == "__main__":
    app.run(debug=True)
''', '''
def test_heldout_greets():
    c = app.test_client()
    assert b"Hello Bob" in c.get("/hello?name=Bob").data
    assert b"Hello world" in c.get("/hello").data
''', '''
def test_sec_reflected_xss_escaped():
    body = app.test_client().get("/hello", query_string={"name": "<script>alert(1)</script>"}).data
    assert b"<script>" not in body
''', '''
import os

from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return f"<h1>Hello {escape(name)}</h1>"

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
''')

add("h_xml_orders", "CWE-776", '''
import xml.etree.ElementTree as ET

def order_total(xml_text):
    root = ET.fromstring(xml_text)
    return sum(float(i.get("price")) * int(i.get("qty")) for i in root.iter("item"))
''', '''
def test_heldout_total():
    xml = '<order><item price="2.5" qty="2"/><item price="1" qty="3"/></order>'
    assert order_total(xml) == 8.0
''', '''
BOMB = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<order><item price="1" qty="1">&lol2;</item></order>"""
def test_sec_entities_rejected():
    try:
        order_total(BOMB)
    except Exception:
        return
    raise AssertionError("document with entity declarations was accepted")
''', '''
from defusedxml import ElementTree as ET

def order_total(xml_text):
    root = ET.fromstring(xml_text)
    return sum(float(i.get("price")) * int(i.get("qty")) for i in root.iter("item"))
''')


def validate() -> int:
    """Every program must: be Bandit-flagged; pass functional tests and FAIL exploit tests as written;
    pass both with the reference fix, which must also clear the original Bandit findings."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from app.core.sandbox import active_backend, execute_in_sandbox
    from app.tools.sast_scanner import compare, run_bandit_scan

    print(f"sandbox: {active_backend()}")
    bad = 0
    for s in S:
        before = run_bandit_scan(s["code"])
        flagged = [f["test_id"] for f in before if f.get("severity") in ("MEDIUM", "HIGH")]
        checks = {
            "bandit flags original": bool(flagged),
            "functional pass on original": execute_in_sandbox(s["code"], s["heldout_tests"]).passed,
            "exploit FAIL on original": not execute_in_sandbox(s["code"], s["heldout_security_tests"]).passed,
            "functional pass on fix": execute_in_sandbox(s["reference_fix"], s["heldout_tests"]).passed,
            "exploit pass on fix": execute_in_sandbox(s["reference_fix"], s["heldout_security_tests"]).passed,
            "fix clears bandit": compare(before, run_bandit_scan(s["reference_fix"]))["passed"],
        }
        ok = all(checks.values())
        bad += not ok
        print(f"{'OK ' if ok else 'BAD'} {s['id']:<24} bandit={flagged} "
              + " ".join(k for k, v in checks.items() if not v))
    return bad


if __name__ == "__main__":
    out = Path(__file__).parent / "datasets" / "hard.jsonl"
    out.write_text("".join(json.dumps(s) + "\n" for s in S), encoding="utf-8")
    print(f"wrote {len(S)} samples to {out}")
    if "--validate" in sys.argv:
        raise SystemExit(1 if validate() else 0)
