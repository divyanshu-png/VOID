import type { Health, OracleMode, ReplayDoc, ReplayMeta, RepoScan, StreamEvent } from "./types";

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* not JSON */
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => fetch("/health").then((r) => json<Health>(r)),
  samples: () => fetch("/api/v1/samples").then((r) => json<{ samples: { id: string; cwe: string; code: string }[] }>(r)),
  demos: () => fetch("/api/v1/repo/demos").then((r) => json<{ repos: string[] }>(r)),
  randomRepo: (user: string) =>
    fetch(`/api/v1/repo/random?user=${encodeURIComponent(user)}`).then((r) => json<{ url: string }>(r)),
  scanRepo: (url: string, min_severity = "MEDIUM") =>
    fetch("/api/v1/repo/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, min_severity, limit: 30 }),
    }).then((r) => json<RepoScan>(r)),
  replays: () => fetch("/api/v1/replays").then((r) => json<{ replays: ReplayMeta[] }>(r)),
  replay: (id: string) => fetch(`/api/v1/replays/${id}`).then((r) => json<ReplayDoc>(r)),
};

/** POST + Server-Sent Events. EventSource only supports GET, so we parse the stream by hand. */
export async function streamPost(
  path: string,
  body: unknown,
  onEvent: (e: StreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
    body: JSON.stringify(body),
    signal,
  });
  if (!res.ok || !res.body) {
    await json(res);
    return;
  }
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx: number;
    while ((idx = buffer.indexOf("\n\n")) >= 0) {
      const block = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      let event = "message";
      const data: string[] = [];
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) event = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
      }
      if (data.length) onEvent({ event, data: JSON.parse(data.join("\n")) });
    }
  }
}

export function auditStream(
  code: string,
  oracle_mode: OracleMode,
  onEvent: (e: StreamEvent) => void,
  signal?: AbortSignal,
) {
  return streamPost("/api/v1/audit/stream", { code, language: "python", oracle_mode }, onEvent, signal);
}

export function repoRunStream(
  url: string,
  target_ids: string[],
  oracle_mode: OracleMode,
  onEvent: (e: StreamEvent) => void,
  signal?: AbortSignal,
) {
  return streamPost(
    "/api/v1/repo/run",
    { url, target_ids, oracle_mode, max_targets: Math.max(1, target_ids.length) },
    onEvent,
    signal,
  );
}

/** Play a recorded run back with its original timing (speed-up factor `speed`). */
export function playReplay(
  doc: ReplayDoc,
  speed: number,
  onEvent: (e: StreamEvent) => void,
): () => void {
  const timers: number[] = [];
  for (const ev of doc.events) {
    timers.push(window.setTimeout(() => onEvent({ event: ev.event, data: ev.data }), (ev.t * 1000) / speed));
  }
  return () => timers.forEach((t) => window.clearTimeout(t));
}
