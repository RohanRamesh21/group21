import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig(({ mode }) => ({
  plugins: [react(), tailwindcss()],
  // GUARDIAN_API lets a second backend (e.g. a test server on another port) sit behind the dev server.
  server: { port: 5173, proxy: { "/api": loadEnv(mode, ".", "GUARDIAN_API").GUARDIAN_API ?? "http://127.0.0.1:8765" } },
}));
