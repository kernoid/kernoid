<!-- SPDX-License-Identifier: MIT -->
<!-- Projects (as in Zitadel): roles of one's own applications, who holds them (authorizations), and which other
     tenants may use the project (grants). The applications are in Applications.svelte. -->
<script lang="ts">
  import Project from "./Project.svelte";
  import ProjectList from "./ProjectList.svelte";

  let { id }: { id: string | undefined } = $props();
</script>

{#if id}
  {#key id}
    <Project {id} />
  {/key}
{:else}
  <ProjectList />
{/if}
