import { applyEvent, emptyRun, startRun } from "./runReducer";
import type { RepoScan, RunState, StreamEvent } from "./types";

export interface RepoState {
  status: "idle" | "scanning" | "scanned" | "running" | "done" | "error";
  scan?: RepoScan;
  runs: Record<string, RunState>;
  current?: string;
  summary?: Record<string, number>;
  error?: string;
  replayId?: string;
}

export const emptyRepo = (): RepoState => ({ status: "idle", runs: {} });

export function applyRepoEvent(prev: RepoState, ev: StreamEvent): RepoState {
  const s: RepoState = { ...prev, runs: { ...prev.runs } };
  const d = ev.data || {};
  switch (ev.event) {
    case "start":
      s.status = "running";
      s.replayId = d.replay_id;
      s.summary = undefined;
      return s;
    case "scan":
      s.scan = d;
      for (const id of d.selected || []) {
        const t = d.targets.find((x: { id: string }) => x.id === id);
        s.runs[id] = emptyRun(t?.snippet || "");
      }
      return s;
    case "target_start": {
      const t = s.scan?.targets.find((x) => x.id === d.id);
      s.runs[d.id] = startRun(t?.snippet || "");
      s.current = d.id;
      return s;
    }
    case "node":
    case "focus":
    case "target_done":
    case "target_error": {
      const id = d.target;
      if (!id) return s;
      s.runs[id] = applyEvent(s.runs[id] || startRun(""), ev);
      return s;
    }
    case "summary":
      s.summary = d;
      s.status = "done";
      s.current = undefined;
      return s;
    case "error":
      s.status = "error";
      s.error = d.message;
      return s;
    default:
      return s;
  }
}
