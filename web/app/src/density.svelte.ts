// SPDX-License-Identifier: MIT
// Comfortable or compact: how much room rows and controls take. Kept in the browser like the theme; `data-density`
// on <html> picks the spacing in style.css.

export type Density = "comfortable" | "compact";

const KEY = "kernoid-density";

function stored(): Density {
  try {
    return localStorage.getItem(KEY) === "compact" ? "compact" : "comfortable";
  } catch {
    return "comfortable";
  }
}

function apply(density: Density): void {
  document.documentElement.setAttribute("data-density", density);
}

const current = $state({ density: stored() });
apply(current.density);

export function density(): Density {
  return current.density;
}

export function setDensity(density: Density): void {
  try {
    localStorage.setItem(KEY, density);
  } catch {
    // Without storage the choice lasts until the page is left.
  }
  apply(density);
  current.density = density;
}
