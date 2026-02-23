<script lang="ts">
  import type { JSONWebSignature } from '../../proto/discocrypto/v1/jwk_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';

  let { jws }: { jws: JSONWebSignature } = $props();
</script>

<Section title="JSON Web Signature" accent="yellow">
  <Field label="Signatures" value={jws.signatures.length.toString()} />
  {#if jws.payload.length > 0}
    <Field label="Payload" value="{jws.payload.length} bytes" />
  {/if}
</Section>

{#each jws.signatures as sig, i}
  <Section title="Signature {i + 1}" accent="yellow" defaultOpen={i === 0}>
    {#if sig.protectedHeader}
      {#if sig.protectedHeader.alg}
        <Field label="Algorithm" value={sig.protectedHeader.alg} />
      {/if}
      {#if sig.protectedHeader.kid}
        <Field label="Key ID" value={sig.protectedHeader.kid} mono />
      {/if}
      {#if sig.protectedHeader.typ}
        <Field label="Type" value={sig.protectedHeader.typ} />
      {/if}
    {/if}
    {#if sig.header}
      {#if sig.header.alg}
        <Field label="Alg (Unprotected)" value={sig.header.alg} />
      {/if}
      {#if sig.header.kid}
        <Field label="Key ID (Unprotected)" value={sig.header.kid} mono />
      {/if}
    {/if}
    <ByteDisplay bytes={sig.signature} label="Signature" />
  </Section>
{/each}

{#if jws.payload.length > 0}
  <Section title="Payload" accent="yellow" defaultOpen={false}>
    <ByteDisplay bytes={jws.payload} />
  </Section>
{/if}
