import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// During dev, proxy API calls to a locally-running bulwark server.
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:3000",
    },
  },
});
