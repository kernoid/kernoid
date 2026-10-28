// SPDX-License-Identifier: MIT
// The theme chosen in the web app (web/app/src/theme.ts, same key and origin): light or dark overrides the system's.

export function applyTheme(): void {
  try {
    const value = localStorage.getItem("kernoid-theme");
    if (value === "light" || value === "dark") document.documentElement.setAttribute("data-theme", value);
  } catch {
    // Without storage the system decides.
  }
}
