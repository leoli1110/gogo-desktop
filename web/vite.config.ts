import { defineConfig } from "vite";

// The Rust server embeds web/dist. During development, run the server on
// 127.0.0.1:4680 and `npm run dev`; API calls are proxied to it.
export default defineConfig({
  build: { outDir: "dist", emptyOutDir: true, assetsInlineLimit: 0, sourcemap: false },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://127.0.0.1:4680", changeOrigin: true, headers: { origin: "http://127.0.0.1:4680" } },
    },
  },
});
