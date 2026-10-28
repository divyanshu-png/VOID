import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, API calls are proxied to the FastAPI backend on :8000.
// `npm run build` writes to dist/, which the backend serves at http://localhost:8000/.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true },
      "/health": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
