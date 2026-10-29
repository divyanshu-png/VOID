import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { createConnection } from "node:net";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

const BACKEND = resolve(__dirname, "../backend");

function portInUse(port: number): Promise<boolean> {
  return new Promise((done) => {
    const sock = createConnection({ port, host: "127.0.0.1" });
    sock.once("connect", () => (sock.end(), done(true)));
    sock.once("error", () => done(false));
  });
}

/** `npm run dev` also starts the FastAPI backend on :8000 (unless one is already running) and stops it on exit. */
function backend(): Plugin {
  let proc: ChildProcess | undefined;
  const stop = () => proc?.kill();
  return {
    name: "void-backend",
    apply: "serve",
    async configureServer() {
      if (await portInUse(8000)) return console.log("  backend: already running on :8000");
      const python = resolve(BACKEND, ".venv/bin/python");
      if (!existsSync(python)) return console.warn("  backend: backend/.venv missing, run ./setup.sh first");
      proc = spawn(python, ["-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"], {
        cwd: BACKEND,
        stdio: "inherit",
      });
      process.once("exit", stop);
      process.once("SIGINT", () => (stop(), process.exit()));
      process.once("SIGTERM", () => (stop(), process.exit()));
    },
  };
}

// In dev, API calls are proxied to the FastAPI backend on :8000.
// `npm run build` writes to dist/, which the backend serves at http://localhost:8000/.
export default defineConfig({
  plugins: [react(), backend()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
