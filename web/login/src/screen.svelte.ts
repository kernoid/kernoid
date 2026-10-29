// SPDX-License-Identifier: MIT
// What the page shows: one screen at a time – a component and its props. The steps of logging in (flow.ts,
// factors.ts, …) move from screen to screen with `show`; App.svelte draws the current one and moves the focus there.

import type { Component } from "svelte";

interface Screen {
  component: Component<any>;
  props: Record<string, unknown>;
  /** Counts screens, so that showing the same component again starts it afresh. */
  turn: number;
}

const current = $state<{ screen: Screen | undefined }>({ screen: undefined });
let turns = 0;

export function screen(): Screen | undefined {
  return current.screen;
}

export function show<Props extends Record<string, any>>(component: Component<Props>, props: Props): void {
  current.screen = { component: component as Component<any>, props, turn: ++turns };
}
