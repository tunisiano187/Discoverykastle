import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: "http://localhost:8443", changeOrigin: true },
      "/api/v1/ws": {
        target: "ws://localhost:8443",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    outDir: "../server/static/ui",
    emptyOutDir: true,
  },
});
