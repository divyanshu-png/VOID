"""Builds datasets/seed.jsonl: small Bandit-flagged programs with held-out functional tests.

Held-out tests check BEHAVIOUR only (they pass on the vulnerable original), so they
measure whether a patch preserved functionality. They are never shown to the agent.
"""
import json
from pathlib import Path

S = []

def add(id, cwe, code, tests):
    S.append({"id": id, "cwe": cwe, "code": code.strip() + "\n", "heldout_tests": tests.strip() + "\n"})

add("sqli_lookup", "CWE-89", '''
import sqlite3

def get_user(conn, username):
    cur = conn.cursor()
    cur.execute(f"SELECT id, username FROM users WHERE username = '{username}'")
    return cur.fetchall()
''', '''
import sqlite3
def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE users (id INTEGER, username TEXT)")
    c.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
    return c
def test_heldout_finds_user():
    assert get_user(_db(), "alice") == [(1, "alice")]
def test_heldout_missing_user():
    assert get_user(_db(), "carol") == []
''')

add("sqli_search", "CWE-89", '''
import sqlite3

def search_products(conn, term, max_price):
    query = "SELECT name, price FROM products WHERE name LIKE '%" + term + "%' AND price <= " + str(max_price)
    return conn.execute(query).fetchall()
''', '''
import sqlite3
def _db():
    c = sqlite3.connect(":memory:")
    c.execute("CREATE TABLE products (name TEXT, price REAL)")
    c.executemany("INSERT INTO products VALUES (?, ?)", [("red pen", 10), ("blue pen", 30), ("ink", 5)])
    return c
def test_heldout_search():
    assert sorted(search_products(_db(), "pen", 20)) == [("red pen", 10.0)]
''')

add("cmd_ping", "CWE-78", '''
import subprocess

def ping(host):
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out.decode()
''', '''
from unittest import mock
def test_heldout_ping_returns_output():
    with mock.patch("subprocess.check_output", return_value=b"1 packets transmitted") as m:
        assert "transmitted" in ping("example.com")
        assert m.called
''')

add("yaml_config", "CWE-20", '''
import yaml

def load_config(text):
    return yaml.load(text, Loader=yaml.Loader)
''', '''
def test_heldout_yaml():
    assert load_config("a: 1\\nb: [x, y]\\n") == {"a": 1, "b": ["x", "y"]}
''')

add("pickle_session", "CWE-502", '''
import pickle
import base64

def save_session(data):
    return base64.b64encode(pickle.dumps(data)).decode()

def load_session(token):
    return pickle.loads(base64.b64decode(token))
''', '''
def test_heldout_roundtrip():
    d = {"user": "alice", "roles": ["admin"], "n": 3}
    assert load_session(save_session(d)) == d
''')

add("eval_settings", "CWE-95", '''
def parse_setting(value):
    return eval(value)
''', '''
def test_heldout_literals():
    assert parse_setting("42") == 42
    assert parse_setting("[1, 2]") == [1, 2]
    assert parse_setting("{'debug': True}") == {"debug": True}
''')

add("md5_password", "CWE-327", '''
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def check_password(password, stored):
    return hash_password(password) == stored
''', '''
def test_heldout_password_check():
    h = hash_password("s3cret")
    assert isinstance(h, str)
    assert check_password("s3cret", h)
    assert not check_password("wrong", h)
''')

add("bind_all", "CWE-605", '''
import socket

def make_server(port=8080):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    return s
''', '''
from unittest import mock
def test_heldout_binds_port():
    with mock.patch("socket.socket") as sock:
        make_server(9000)
        args = sock.return_value.bind.call_args[0][0]
        assert args[1] == 9000
''')

add("mktemp_report", "CWE-377", '''
import tempfile

def write_report(text):
    path = tempfile.mktemp(suffix=".txt")
    with open(path, "w") as fh:
        fh.write(text)
    return path
''', '''
def test_heldout_report_written():
    p = write_report("hello")
    with open(p) as fh:
        assert fh.read() == "hello"
''')

add("requests_noverify", "CWE-295", '''
import requests

def fetch_status(url):
    r = requests.get(url, verify=False, timeout=5)
    return r.status_code
''', '''
from unittest import mock
def test_heldout_status():
    with mock.patch("requests.get") as g:
        g.return_value.status_code = 200
        assert fetch_status("https://example.com") == 200
''')

add("jinja_noescape", "CWE-79", '''
from jinja2 import Environment

def render_greeting(name):
    env = Environment(autoescape=False)
    return env.from_string("<p>Hello {{ name }}</p>").render(name=name)
''', '''
def test_heldout_render():
    assert render_greeting("Bob") == "<p>Hello Bob</p>"
''')

add("exec_calc", "CWE-95", '''
def run_formula(expr, x):
    scope = {"x": x}
    exec("result = " + expr, {}, scope)
    return scope["result"]
''', '''
def test_heldout_formula():
    assert run_formula("x * 2 + 1", 3) == 7
    assert run_formula("x - 4", 10) == 6
''')

out = Path(__file__).parent / "datasets" / "seed.jsonl"
out.write_text("".join(json.dumps(s) + "\n" for s in S), encoding="utf-8")
print(f"wrote {len(S)} samples to {out}")
