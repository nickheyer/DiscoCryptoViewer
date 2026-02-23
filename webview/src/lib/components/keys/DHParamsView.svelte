<script lang="ts">
  import type { DHParameters } from '../../proto/discocrypto/v1/keys_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';

  let { params }: { params: DHParameters } = $props();
</script>

<Section title="DH Parameters" accent="magenta">
  <Field label="Key Size" value="{params.keySizeBits} bits" />
</Section>

{#if params.p}
  <Section title="Prime (p)" accent="magenta" defaultOpen={false}>
    <ByteDisplay bytes={params.p.value} />
  </Section>
{/if}

{#if params.g}
  <Section title="Generator (g)" accent="magenta" defaultOpen={false}>
    <ByteDisplay bytes={params.g.value} />
  </Section>
{/if}
