"""API smoke tests using the rule-based stub LLM (no key, no network for the LLM)."""
import json

import pytest
from fastapi.testclient import TestClient

from app.core import config
from app.main import app


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STUB_LLM", True)
    monkeypatch.setattr(config, "REPLAY_DIR", tmp_path)
    return TestClient(app)


CODE = 'import yaml\n\ndef load(text):\n    return yaml.load(text, Loader=yaml.Loader)\n'


def test_health(client):
    assert client.get("/health").json()["status"] == "healthy"


def test_audit_returns_verified_patch_and_replay(client):
    r = client.post("/api/v1/audit", json={"code": CODE, "oracle_mode": "dual"}).json()
    assert r["verdict"] == "verified" and "safe_load" in r["refactored_code"]
    replay = client.get(f"/api/v1/replays/{r['replay_id']}").json()
    assert replay["events"][-1]["event"] == "done"


def test_stream_events(client):
    events = []
    with client.stream("POST", "/api/v1/audit/stream", json={"code": CODE}) as resp:
        for line in resp.iter_lines():
            if line.startswith("event:"):
                events.append(line[6:].strip())
    assert events[0] == "start" and events[-1] == "done" and events.count("node") == 5


def test_focus_line_merges_into_file(client):
    code = "import yaml\n\ndef ok():\n    return 1\n\ndef load(text):\n    return yaml.load(text, Loader=yaml.Loader)\n"
    r = client.post("/api/v1/audit", json={"code": code, "focus_line": 7}).json()
    assert r["focus"]["name"] == "load"
    assert "def ok():" in r["merged_file"] and "safe_load" in r["merged_file"]


def test_empty_code_rejected(client):
    assert client.post("/api/v1/audit", json={"code": "  "}).status_code == 400


def test_samples(client):
    s = client.get("/api/v1/samples").json()["samples"]
    assert len(s) >= 10 and all("code" in x for x in s)
