<script lang="ts">
  import type { CTSignedCertificateTimestamp } from '../../proto/discocrypto/v1/ct_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { formatTimestamp, hexColonFormat, hashAlgorithmName, signatureAlgorithmName } from '../../utils/format';

  let { sct }: { sct: CTSignedCertificateTimestamp } = $props();
</script>

<Section title="Signed Certificate Timestamp" accent="purple">
  <Field label="Version" value="v{sct.version}" />
  <Field label="Timestamp" value={formatTimestamp(sct.timestamp)} />
  {#if sct.logId.length > 0}
    <Field label="Log ID" value={hexColonFormat(sct.logId)} mono />
  {/if}
</Section>

{#if sct.signature}
  <Section title="Signature" accent="purple" defaultOpen={false}>
    <Field label="Hash Algorithm" value={hashAlgorithmName(sct.signature.hashAlgorithm)} />
    <Field label="Signature Alg" value={signatureAlgorithmName(sct.signature.signatureAlgorithm)} />
    {#if sct.signature.signature.length > 0}
      <ByteDisplay bytes={sct.signature.signature} label="Signature" />
    {/if}
  </Section>
{/if}

{#if sct.extensions.length > 0}
  <Section title="Extensions" accent="purple" defaultOpen={false}>
    <ByteDisplay bytes={sct.extensions} />
  </Section>
{/if}
