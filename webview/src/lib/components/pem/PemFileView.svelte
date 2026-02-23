<script lang="ts">
  import type { PemFile } from '../../proto/discocrypto/v1/pem_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { pemTypeName, byteSize } from '../../utils/format';

  let { pem }: { pem: PemFile } = $props();
</script>

<Section title="PEM Blocks ({pem.blocks.length})" accent="blue">
  {#each pem.blocks as block, i}
    <div style="margin-bottom: 10px; padding: 8px; background: var(--dc-surface-1); border-radius: 4px; border: 1px solid var(--dc-border)">
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px">
        <Badge text="Block {i + 1}" color="blue" />
        <span style="font-weight: 600; font-size: 0.9em">{block.type || pemTypeName(block.pemType)}</span>
      </div>
      <Field label="PEM Type" value={pemTypeName(block.pemType)} />
      <Field label="Data Size" value={byteSize(block.data)} />

      {#if Object.keys(block.headers).length > 0}
        <div style="margin-top: 4px">
          <span class="dc-field-label">Headers</span>
          <div class="dc-map">
            {#each Object.entries(block.headers) as [k, v]}
              <div class="dc-map-entry">
                <span class="dc-map-key">{k}</span>
                <span class="dc-map-value">{v}</span>
              </div>
            {/each}
          </div>
        </div>
      {/if}
    </div>
  {/each}
</Section>
