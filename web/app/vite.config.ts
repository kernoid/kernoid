// SPDX-License-Identifier: MIT
// The build goes to dist/, which the kernoid binary embeds and serves at /app: the app (index.html) and what a link
// opens (link.html). In development, http.web_app may name dist/ instead.
/// <reference types="vitest/config" />
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

export default defineConfig({
  base: "/app/",
  plugins: [svelte()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
    assetsInlineLimit: 0,
    rollupOptions: { input: { app: "index.html", link: "link.html" } },
  },
  resolve: { alias: { "@kernoid/sdk": new URL("../sdk/src/index.ts", import.meta.url).pathname } },
  // The tests are of plain functions: no browser needed.
  test: { environment: "node" },
});
