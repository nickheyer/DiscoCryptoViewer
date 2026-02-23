<script lang="ts">
  import type { PGPSignature } from '../../proto/discocrypto/v1/pgp_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import {
    pgpSignatureTypeName, pgpKeyAlgorithmName, hashAlgorithmName,
    formatTimestamp, pgpKeyFlagName,
  } from '../../utils/format';

  let { sig }: { sig: PGPSignature } = $props();
</script>

<Section title="PGP Signature" accent="orange">
  <Field label="Version" value="v{sig.version}" />
  <Field label="Type" value={pgpSignatureTypeName(sig.sigType)} />
  <Field label="Pub Key Alg" value={pgpKeyAlgorithmName(sig.pubKeyAlgorithm)} />
  <Field label="Hash Alg" value={hashAlgorithmName(sig.hashAlgorithm)} />
  <Field label="Issuer Key ID" value={sig.issuerKeyId} mono />
  <Field label="Created" value={formatTimestamp(sig.creationTime)} />
  {#if sig.expirationTime}
    <Field label="Expires" value={formatTimestamp(sig.expirationTime)} />
  {/if}
</Section>

{#if sig.keyFlags.length > 0}
  <Section title="Key Flags" accent="orange">
    <div class="dc-tags">
      {#each sig.keyFlags as flag}
        <Badge text={pgpKeyFlagName(flag)} color="orange" />
      {/each}
    </div>
  </Section>
{/if}

{#if sig.notations.length > 0}
  <Section title="Notations ({sig.notations.length})" accent="orange" defaultOpen={false}>
    {#each sig.notations as n}
      <div class="dc-map-entry">
        <span class="dc-map-key">{n.name}</span>
        <span class="dc-map-value">{n.value}{#if n.humanReadable} <Badge text="Human Readable" color="green" />{/if}</span>
      </div>
    {/each}
  </Section>
{/if}

{#if sig.raw.length > 0}
  <Section title="Raw Signature" accent="orange" defaultOpen={false}>
    <ByteDisplay bytes={sig.raw} />
  </Section>
{/if}
