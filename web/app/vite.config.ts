// SPDX-License-Identifier: MIT
// kernoid serves the build at /app (http.web_app): the app (index.html) and what a link opens (link.html).
/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

export default defineConfig({
  base: "/app/",
  plugins: [solid()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    rollupOptions: { input: { app: "index.html", link: "link.html" } },
  },
  resolve: { alias: { "@kernoid/sdk": new URL("../sdk/src/index.ts", import.meta.url).pathname } },
  // The tests are of plain functions: no browser needed.
  test: { environment: "node" },
});
