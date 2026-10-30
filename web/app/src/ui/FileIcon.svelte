<!-- SPDX-License-Identifier: MIT -->
<!-- A file's icon by what it is: image, audio, video, PDF, text or anything else (files/kind.ts). -->
<script lang="ts">
  import { File, FileAudio, FileImage, FileText, FileType, FileVideo } from "@lucide/svelte";

  import { kindOf } from "../files/kind.js";

  let { name, type, size = 18 }: { name: string; type?: string | null | undefined; size?: number } = $props();

  const ICONS = { image: FileImage, audio: FileAudio, video: FileVideo, pdf: FileType, text: FileText, other: File };
  const Icon = $derived(ICONS[kindOf(name, type)]);
</script>

<Icon {size} class={`file-icon ${kindOf(name, type)}`} aria-hidden="true" />
