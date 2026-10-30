<!-- SPDX-License-Identifier: MIT -->
<!-- One tooltip for the whole app: whatever carries `data-tip` shows it on hover or keyboard focus, placed above (or
     below, near the top) in the window – so no scrolling container cuts it off. -->
<script lang="ts">
  let text = $state<string>();
  let x = $state(0);
  let y = $state(0);
  let below = $state(false);
  let timer: ReturnType<typeof setTimeout> | undefined;

  function show(target: EventTarget | null, delay: number): void {
    const element = target instanceof Element ? target.closest<HTMLElement>("[data-tip]") : null;
    clearTimeout(timer);
    if (!element) {
      text = undefined;
      return;
    }
    timer = setTimeout(() => {
      const box = element.getBoundingClientRect();
      below = box.top < 48;
      x = Math.min(Math.max(box.left + box.width / 2, 60), window.innerWidth - 60);
      y = below ? box.bottom + 8 : box.top - 8;
      text = element.dataset.tip;
    }, delay);
  }

  function hide(): void {
    clearTimeout(timer);
    text = undefined;
  }
</script>

<svelte:document
  onpointerover={(event) => event.pointerType === "mouse" && show(event.target, 350)}
  onfocusin={(event) => event.target instanceof HTMLElement && event.target.matches(":focus-visible") && show(event.target, 0)}
  onfocusout={hide}
  onpointerdown={hide}
  onkeydown={(event) => event.key === "Escape" && hide()}
/>

{#if text}
  <div class="tooltip" class:below role="tooltip" style:left={`${x}px`} style:top={`${y}px`}>{text}</div>
{/if}
