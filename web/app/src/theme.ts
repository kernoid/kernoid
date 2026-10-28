// SPDX-License-Identifier: MIT
// Light, dark or as the system is: kept in the browser for the instance's origin, so the login UI follows it too
// (web/login/src/theme.ts reads the same key). `data-theme` on <html> overrides the system's choice in style.css.

import { createSignal } from "solid-js";

export type Theme = "system" | "light" | "dark";

const KEY = "kernoid-theme";
export const THEMES: Theme[] = ["system", "light", "dark"];

function stored(): Theme {
  try {
    const value = localStorage.getItem(KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

function apply(theme: Theme): void {
  if (theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", theme);
}

const [current, setCurrent] = createSignal<Theme>(stored());
apply(current());

export const theme = current;

export function setTheme(theme: Theme): void {
  try {
    if (theme === "system") localStorage.removeItem(KEY);
    else localStorage.setItem(KEY, theme);
  } catch {
    // Without storage the choice lasts until the page is left.
  }
  apply(theme);
  setCurrent(theme);
}
