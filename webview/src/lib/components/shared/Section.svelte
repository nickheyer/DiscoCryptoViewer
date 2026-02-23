<script lang="ts">
  import type { Snippet } from 'svelte';

  let { title, accent = 'cyan', defaultOpen = true, children }: {
    title: string;
    accent?: string;
    defaultOpen?: boolean;
    children: Snippet;
  } = $props();

  // svelte-ignore state_referenced_locally
    let open = $state(defaultOpen);
</script>

<div class="dc-section accent-{accent}">
  <button class="dc-section-header" onclick={() => open = !open}>
    <span class="dc-section-chevron" class:open>&#9656;</span>
    <span>{title}</span>
  </button>
  {#if open}
    <div class="dc-section-content">
      {@render children()}
    </div>
  {/if}
</div>
