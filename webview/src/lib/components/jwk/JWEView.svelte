<script lang="ts">
  import type { JSONWebEncryption } from '../../proto/discocrypto/v1/jwk_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';

  let { jwe }: { jwe: JSONWebEncryption } = $props();
</script>

<Section title="JSON Web Encryption" accent="yellow">
  {#if jwe.header}
    {#if jwe.header.alg}
      <Field label="Algorithm" value={jwe.header.alg} />
    {/if}
    {#if jwe.header.enc}
      <Field label="Encryption" value={jwe.header.enc} />
    {/if}
    {#if jwe.header.kid}
      <Field label="Key ID" value={jwe.header.kid} mono />
    {/if}
    {#if jwe.header.zip}
      <Field label="Compression" value={jwe.header.zip} />
    {/if}
    {#if jwe.header.typ}
      <Field label="Type" value={jwe.header.typ} />
    {/if}
    {#if jwe.header.cty}
      <Field label="Content Type" value={jwe.header.cty} />
    {/if}
  {/if}
</Section>

<Section title="Encrypted Content" accent="yellow">
  <Field label="Encrypted Key" value="{jwe.encryptedKey.length} bytes" />
  <Field label="IV" value="{jwe.iv.length} bytes" />
  <Field label="Ciphertext" value="{jwe.ciphertext.length} bytes" />
  <Field label="Auth Tag" value="{jwe.tag.length} bytes" />
  {#if jwe.aad.length > 0}
    <Field label="AAD" value="{jwe.aad.length} bytes" />
  {/if}
</Section>

{#if jwe.iv.length > 0}
  <Section title="IV" accent="yellow" defaultOpen={false}>
    <ByteDisplay bytes={jwe.iv} />
  </Section>
{/if}

{#if jwe.tag.length > 0}
  <Section title="Authentication Tag" accent="yellow" defaultOpen={false}>
    <ByteDisplay bytes={jwe.tag} />
  </Section>
{/if}
