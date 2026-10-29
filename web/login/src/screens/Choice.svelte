<!-- SPDX-License-Identifier: MIT -->
<!-- A screen of text and buttons: a notice, what to know, a list, and what one can do next. -->
<script lang="ts" module>
  export interface Choose {
    label: string;
    run: () => Promise<void>;
    kind?: string;
  }
</script>

<script lang="ts">
  import Action from "../ui/Action.svelte";
  import Card from "../ui/Card.svelte";
  import Message from "../ui/Message.svelte";

  let {
    title,
    notice,
    text,
    items = [],
    note,
    link,
    actions = [],
  }: {
    title: string;
    notice?: { text: string; kind?: "error" | "info" } | undefined;
    text?: string | undefined;
    items?: string[];
    note?: string | undefined;
    link?: { href: string; text: string } | undefined;
    actions?: Choose[];
  } = $props();
</script>

<Card {title}>
  {#if notice}
    <Message text={notice.text} kind={notice.kind ?? "error"} />
  {/if}
  {#if text}
    <p>{text}</p>
  {/if}
  {#if items.length > 0}
    <ul class="list">
      {#each items as item, index (index)}
        <li>{item}</li>
      {/each}
    </ul>
  {/if}
  {#if note}
    <p class="muted">{note}</p>
  {/if}
  {#if link}
    <p><a href={link.href}>{link.text}</a></p>
  {/if}
  {#each actions as action, index (index)}
    <Action label={action.label} run={action.run} kind={action.kind ?? "secondary"} />
  {/each}
</Card>
