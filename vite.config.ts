import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Fixed port: the Tauri dev shell points at it.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    // Active parses write DuckDB files continuously. Generated case output
    // must not reload the review UI while an analyst is scrolling its grid.
    watch: { ignored: ["**/cases/**"] },
  },
  build: { target: "es2021" },
});
