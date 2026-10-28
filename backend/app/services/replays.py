"""Record runs so they can be played back later (offline demo / viva safety net)."""
from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any, Dict, List, Optional

from app.core import config


class Recorder:
    def __init__(self, kind: str, title: str, meta: Optional[Dict[str, Any]] = None):
        self.id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        self.kind, self.title, self.meta = kind, title, meta or {}
        self.started = time.time()
        self.events: List[Dict[str, Any]] = []

    def add(self, event: str, data: Dict[str, Any]) -> Dict[str, Any]:
        rec = {"t": round(time.time() - self.started, 3), "event": event, "data": data}
        self.events.append(rec)
        return rec

    def save(self) -> str:
        config.REPLAY_DIR.mkdir(parents=True, exist_ok=True)
        doc = {"id": self.id, "kind": self.kind, "title": self.title, "meta": self.meta,
               "created": time.strftime("%Y-%m-%d %H:%M:%S"), "duration_s": round(time.time() - self.started, 2),
               "events": self.events}
        (config.REPLAY_DIR / f"{self.id}.json").write_text(json.dumps(doc, default=str), encoding="utf-8")
        return self.id


def list_replays() -> List[Dict[str, Any]]:
    if not config.REPLAY_DIR.exists():
        return []
    out = []
    for p in sorted(config.REPLAY_DIR.glob("*.json"), reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            item = {k: d.get(k) for k in ("id", "kind", "title", "created", "duration_s")}
            item["meta"] = {k: (v[:160] if isinstance(v, str) else v) for k, v in (d.get("meta") or {}).items()}
            out.append(item)
        except Exception:
            continue
    return out


def load_replay(replay_id: str) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"[\w.-]+", replay_id):
        return None
    p = config.REPLAY_DIR / f"{replay_id}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None
