<script lang="ts">
  import type { JSONWebKeySet } from '../../proto/discocrypto/v1/jwk_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';

  let { jwks }: { jwks: JSONWebKeySet } = $props();
</script>

<Section title="JSON Web Key Set ({jwks.keys.length} keys)" accent="yellow">
  {#each jwks.keys as key, i}
    <div style="margin-bottom: 8px; padding: 8px; background: var(--dc-surface-1); border-radius: 4px; border: 1px solid var(--dc-border)">
      <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px">
        <Badge text="Key {i + 1}" color="yellow" />
        <span style="font-weight: 600; font-size: 0.9em">{key.kty}</span>
        {#if key.isPrivate}
          <Badge text="Private" color="red" />
        {/if}
      </div>
      {#if key.kid}
        <Field label="Key ID" value={key.kid} mono />
      {/if}
      {#if key.alg}
        <Field label="Algorithm" value={key.alg} />
      {/if}
      {#if key.use}
        <Field label="Use" value={key.use} />
      {/if}
      {#if key.keyOps.length > 0}
        <div class="dc-tags" style="margin-top: 4px">
          {#each key.keyOps as op}
            <Badge text={op} color="yellow" />
          {/each}
        </div>
      {/if}
    </div>
  {/each}
</Section>
