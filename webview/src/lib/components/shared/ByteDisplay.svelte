<script lang="ts">
  import { hexColonFormat } from '../../utils/format';

  let { bytes, label = '', maxBytes = 64 }: {
    bytes: Uint8Array;
    label?: string;
    maxBytes?: number;
  } = $props();

  let expanded = $state(false);

  let display = $derived(
    expanded || bytes.length <= maxBytes
      ? hexColonFormat(bytes)
      : hexColonFormat(bytes.slice(0, maxBytes)) + '\u2026'
  );

  let canExpand = $derived(bytes.length > maxBytes);
</script>

{#if bytes.length > 0}
  <div>
    {#if label}
      <div class="dc-field-label" style="margin-bottom: 4px">{label}</div>
    {/if}
    <div class="dc-bytes">{display}</div>
    {#if canExpand}
      <button class="dc-expand-btn" onclick={() => expanded = !expanded}>
        {expanded ? 'Show less' : `Show all ${bytes.length} bytes`}
      </button>
    {/if}
  </div>
{/if}
