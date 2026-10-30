<!-- SPDX-License-Identifier: MIT -->
<!-- A person as a picture: their own if they uploaded one, else their initials on a colour of their own – the same
     colour for the same address everywhere. -->
<script lang="ts">
  import { avatarOfAddress } from "../avatars.svelte.js";

  let { name, address = "", src, size = 32 }: { name: string; address?: string; src?: string | undefined; size?: number } = $props();

  /** Up to two letters: first and last word, or the address before the @. */
  const initials = $derived.by(() => {
    const words = ((name.includes("@") ? name.split("@")[0] : name) || address.split("@")[0] || "?")
      .split(/[\s._-]+/)
      .filter(Boolean);
    const first = words[0]?.[0] ?? "?";
    const last = words.length > 1 ? (words[words.length - 1]?.[0] ?? "") : "";
    return (first + last).toUpperCase();
  });

  /** A hue from the address (or the name): stable, spread over the circle. */
  const hue = $derived.by(() => {
    let hash = 0;
    for (const char of (address || name).toLowerCase()) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
    return hash % 360;
  });

  let failed = $state(false);
  // Their picture, if they set one: given, or found by address among the tenant's.
  const picture = $derived(src ?? avatarOfAddress(address));
</script>

<span class="avatar" style:--size={`${size}px`} style:--hue={hue} aria-hidden="true">
  {#if picture && !failed}
    <img src={picture} alt="" onerror={() => (failed = true)} />
  {:else}
    {initials}
  {/if}
</span>
