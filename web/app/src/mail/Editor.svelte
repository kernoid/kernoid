<!-- SPDX-License-Identifier: MIT -->
<!-- Writing with formatting (TipTap, MIT): bold, italic, underline, strike-through, headings, lists, quotes, links.
     What it holds is only what its schema knows – pasted or quoted HTML loses scripts, styles and images on the way
     in –, so its HTML can be sent as it is; the plain text goes alongside for programs that show no HTML. TipTap's
     own stylesheet is off (the page allows no inline styles); style.css has what it needs. -->
<script lang="ts">
  import { Editor } from "@tiptap/core";
  import Placeholder from "@tiptap/extension-placeholder";
  import StarterKit from "@tiptap/starter-kit";
  import {
    Bold,
    Heading2,
    Italic,
    Link,
    List,
    ListOrdered,
    Quote,
    Redo2,
    RemoveFormatting,
    Strikethrough,
    Underline,
    Undo2,
  } from "@lucide/svelte";

  import { t } from "../i18n.js";

  let {
    content = "",
    autofocus = false,
    onchange,
  }: { content?: string; autofocus?: boolean; onchange: (html: string, text: string) => void } = $props();

  let editor = $state<Editor>();
  /** Bumped on every change of the editor, so the toolbar shows what is on. */
  let tick = $state(0);

  function mount(element: HTMLElement): () => void {
    const instance = new Editor({
      element,
      // svelte-ignore state_referenced_locally
      content,
      injectCSS: false,
      // svelte-ignore state_referenced_locally
      autofocus: autofocus ? "start" : false,
      extensions: [
        StarterKit.configure({
          heading: { levels: [2, 3] },
          link: { openOnClick: false, autolink: true, defaultProtocol: "https", protocols: ["mailto"] },
        }),
        Placeholder.configure({ placeholder: t("Write your message …") }),
      ],
      editorProps: { attributes: { class: "editor-body", "aria-label": t("Text"), role: "textbox", "aria-multiline": "true" } },
      onTransaction: () => (tick += 1),
      onUpdate: ({ editor: current }) => onchange(current.getHTML(), current.getText({ blockSeparator: "\n\n" })),
    });
    editor = instance;
    onchange(instance.getHTML(), instance.getText({ blockSeparator: "\n\n" }));
    return () => instance.destroy();
  }

  /** The commands, focusing the editor first only if it lost the focus – focusing again would reset the selection and
   * with it the formatting chosen for what is typed next. */
  function chain() {
    if (!editor) return undefined;
    return editor.isFocused ? editor.chain() : editor.chain().focus();
  }

  function on(name: string, attributes?: Record<string, unknown>): boolean {
    void tick;
    return editor?.isActive(name, attributes) ?? false;
  }

  function link(): void {
    if (!editor) return;
    const current = editor.getAttributes("link").href as string | undefined;
    const href = window.prompt(t("Link to (empty removes it)"), current ?? "https://");
    if (href === null) return;
    if (href.trim() === "") editor.chain().focus().extendMarkRange("link").unsetLink().run();
    else editor.chain().focus().extendMarkRange("link").setLink({ href: href.trim() }).run();
  }

  const tools = $derived([
    { label: "Bold", icon: Bold, active: on("bold"), run: () => chain()?.toggleBold().run() },
    { label: "Italic", icon: Italic, active: on("italic"), run: () => chain()?.toggleItalic().run() },
    { label: "Underline", icon: Underline, active: on("underline"), run: () => chain()?.toggleUnderline().run() },
    { label: "Strike-through", icon: Strikethrough, active: on("strike"), run: () => chain()?.toggleStrike().run() },
    null,
    { label: "Heading", icon: Heading2, active: on("heading", { level: 2 }), run: () => chain()?.toggleHeading({ level: 2 }).run() },
    { label: "List", icon: List, active: on("bulletList"), run: () => chain()?.toggleBulletList().run() },
    { label: "Numbered list", icon: ListOrdered, active: on("orderedList"), run: () => chain()?.toggleOrderedList().run() },
    { label: "Quote", icon: Quote, active: on("blockquote"), run: () => chain()?.toggleBlockquote().run() },
    { label: "Link", icon: Link, active: on("link"), run: link },
    null,
    { label: "Remove formatting", icon: RemoveFormatting, active: false, run: () => chain()?.unsetAllMarks().clearNodes().run() },
    { label: "Undo", icon: Undo2, active: false, run: () => chain()?.undo().run() },
    { label: "Redo", icon: Redo2, active: false, run: () => chain()?.redo().run() },
  ]);
</script>

<div class="editor">
  <div class="editor-tools" role="toolbar" aria-label={t("Formatting")}>
    {#each tools as tool, index (index)}
      {#if tool}
        {@const Icon = tool.icon}
        <button
          type="button"
          class="icon quiet small"
          class:on={tool.active}
          aria-pressed={tool.active}
          aria-label={t(tool.label)}
          data-tip={t(tool.label)}
          onmousedown={(event) => event.preventDefault()}
          onclick={tool.run}
        >
          <Icon size={16} />
        </button>
      {:else}
        <span class="divider"></span>
      {/if}
    {/each}
  </div>
  <div class="editor-area" {@attach mount}></div>
</div>
