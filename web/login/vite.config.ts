// SPDX-License-Identifier: MIT
// kernoid serves the build at /login (http.login_ui).
import { svelte } from "@sveltejs/vite-plugin-svelte";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [svelte()],
  base: "/login/",
  build: { outDir: "dist", emptyOutDir: true, sourcemap: true },
  resolve: { alias: { "@kernoid/sdk": new URL("../sdk/src/index.ts", import.meta.url).pathname } },
});
