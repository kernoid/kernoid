// SPDX-License-Identifier: MIT
// What every view shares: the JMAP session (a context), the counters push bumps per type, and resources – values
// loaded from the server that load again when what they depend on changes.

import { getContext, setContext, untrack } from "svelte";

import { t } from "./i18n.js";
import type { Jmap } from "./jmap.js";

const JMAP = Symbol("jmap");

export function provideJmap(jmap: Jmap): void {
  setContext(JMAP, jmap);
}

export function useJmap(): Jmap {
  const jmap = getContext<Jmap | undefined>(JMAP);
  if (!jmap) throw new Error("no JMAP session");
  return jmap;
}

/** Bumped whenever kernoid announces a change (push), per type – views load again what they show. */
const changes = $state<Record<string, number>>({});

export function changed(type: string): number {
  return changes[type] ?? 0;
}

export function touch(...types: string[]): void {
  for (const type of types) changes[type] = (changes[type] ?? 0) + 1;
}

/** A value loaded from the server: the value, the failure, whether it is loading. */
export class Resource<T> {
  value = $state<T | undefined>();
  error = $state<unknown>();
  loading = $state(false);
  #load: () => Promise<T>;
  #run = 0;

  constructor(load: () => Promise<T>, initial?: T) {
    this.#load = load;
    this.value = initial;
  }

  /** Loaded and not failed. */
  get ready(): boolean {
    return !this.loading && this.error === undefined && this.value !== undefined;
  }

  /** Loads again; an answer that arrives after a newer request is dropped. */
  async refetch(): Promise<void> {
    const run = ++this.#run;
    this.loading = true;
    try {
      const value = await this.#load();
      if (run === this.#run) {
        this.value = value;
        this.error = undefined;
      }
    } catch (failure) {
      if (run === this.#run) this.error = failure;
    } finally {
      if (run === this.#run) this.loading = false;
    }
  }

  /** Replaces the value without loading (an answer the caller has already). */
  set(value: T): void {
    this.value = value;
  }

  /** Loads with another function from now on (the source changed). */
  with(load: () => Promise<T>): this {
    this.#load = load;
    return this;
  }

  clear(): void {
    this.#run++;
    this.value = undefined;
    this.error = undefined;
    this.loading = false;
  }
}

/**
 * A resource that loads `load(key)` whenever `source` gives another key – and nothing while it gives `undefined`,
 * `null` or `false`. Reading `changed(type)` inside `source` loads again on push. Call it while a component is set up.
 */
export function resource<K, T>(source: () => K | undefined | null | false, load: (key: K) => Promise<T>, initial?: T): Resource<T> {
  const value = new Resource<T>(() => Promise.reject(new Error("not loaded")), initial);
  $effect(() => {
    const key = source();
    untrack(() => {
      if (key === undefined || key === null || key === false) value.clear();
      else void value.with(() => load(key)).refetch();
    });
  });
  return value;
}

/** A resource loaded once when the component is set up (and with `refetch`). */
export function loaded<T>(load: () => Promise<T>, initial?: T): Resource<T> {
  return resource(() => true, () => load(), initial);
}

/** The text of an empty list – or "Loading" while its resource has not answered yet. */
export function emptyText(value: Resource<unknown>, text: string): string {
  return value.loading ? t("Loading") : text;
}

/** A failure as text. */
export function message(failure: unknown): string {
  return failure instanceof Error ? failure.message : String(failure);
}
