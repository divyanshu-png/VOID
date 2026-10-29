import type { Attempt, RunState, StageId, StreamEvent } from "./types";

export const STAGES: { id: StageId; label: string; detail: string }[] = [
  { id: "ast_parser", label: "Pre-checks", detail: "AST · Bandit · PyPI" },
  { id: "security_audit", label: "Audit", detail: "LLM security review" },
  { id: "refactor", label: "Repair", detail: "Patch + tests" },
  { id: "sandbox", label: "Verify", detail: "Re-scan + run tests" },
  { id: "presentation", label: "Result", detail: "Verdict + diff" },
];

export function emptyRun(code = ""): RunState {
  return {
    status: "idle",
    code,
    stages: { ast_parser: "pending", security_audit: "pending", refactor: "pending", sandbox: "pending", presentation: "pending" },
    sastBefore: [],
    packages: [],
    attempts: [],
  };
}

export function startRun(code: string): RunState {
  const s = emptyRun(code);
  s.status = "running";
  s.stages.ast_parser = "active";
  return s;
}

/** Pure reducer shared by live streams and replays. */
export function applyEvent(prev: RunState, ev: StreamEvent): RunState {
  const s: RunState = { ...prev, stages: { ...prev.stages }, attempts: prev.attempts.map((a) => ({ ...a })) };
  const d = ev.data || {};
  switch (ev.event) {
    case "start":
      s.status = "running";
      s.replayId = d.replay_id;
      if (s.stages.ast_parser === "pending") s.stages.ast_parser = "active";
      return s;
    case "focus":
      s.focus = d;
      return s;
    case "node": {
      const node = d.node as StageId | "critic" | "supervisor";
      if (node === "ast_parser") {
        s.ast = d.ast_metadata;
        s.sastBefore = d.sast_before || [];
        s.packages = d.package_report || [];
        s.stages.ast_parser = d.verdict === "invalid_input" ? "failed" : "done";
        if (d.verdict === "invalid_input") {
          s.stages.security_audit = "skipped";
          s.stages.refactor = "skipped";
          s.stages.sandbox = "skipped";
          s.stages.presentation = "active";
        } else s.stages.security_audit = "active";
      } else if (node === "security_audit") {
        s.audit = d.audit;
        s.stages.security_audit = "done";
        if (d.verdict === "clean") {
          s.stages.refactor = "skipped";
          s.stages.sandbox = "skipped";
          s.stages.presentation = "active";
        } else s.stages.refactor = "active";
      } else if (node === "refactor") {
        const a: Attempt = { n: d.attempt, patched_code: d.patched_code, tests: d.tests, notes: d.notes };
        s.attempts.push(a);
        s.stages.refactor = "done";
        s.stages.sandbox = "active";
      } else if (node === "sandbox") {
        const last = s.attempts[s.attempts.length - 1];
        if (last) Object.assign(last, { exec: d.exec, sast: d.sast, accepted: d.accepted, feedback: d.feedback });
        s.stages.sandbox = "done";
        s.stages.refactor = "active"; // provisional: switched to done when the result arrives
        s.stages.presentation = "pending";
      } else if (node === "critic" || node === "supervisor") {
        // Autonomous mode: the critic reviews the patch, then the supervisor picks the next step.
        const last = s.attempts[s.attempts.length - 1];
        if (last) Object.assign(last, { accepted: d.accepted, critic: d.critic, decision: d.decision, feedback: d.feedback });
        const next = d.decision?.action;
        s.stages.sandbox = node === "critic" ? "active" : "done";
        if (node === "supervisor") {
          s.stages.refactor = next === "repair_code" || next === "repair_tests" ? "active" : "done";
          if (next === "reaudit") s.stages.security_audit = "active";
        }
      } else if (node === "presentation") {
        if (s.stages.refactor === "active") s.stages.refactor = "done";
        s.stages.presentation = "done";
      }
      return s;
    }
    case "done":
    case "target_done":
      s.result = d;
      s.status = "done";
      if (s.stages.refactor === "active") s.stages.refactor = "done";
      s.stages.presentation = "done";
      if (d.replay_id) s.replayId = d.replay_id;
      return s;
    case "error":
    case "target_error":
      s.status = "error";
      s.error = d.message;
      return s;
    default:
      return s;
  }
}
