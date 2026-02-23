<script lang="ts">
  import type { AttributeCertificate } from '../../proto/discocrypto/v1/x509_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import DNView from '../shared/DNView.svelte';
  import {
    signatureAlgorithmName, formatTimestamp, bigIntToDecimal, oidName,
  } from '../../utils/format';

  let { cert }: { cert: AttributeCertificate } = $props();
</script>

<Section title="Details" accent="cyan">
  <Field label="Version" value="v{cert.version}" />
  <Field label="Serial Number" value={bigIntToDecimal(cert.serialNumber)} mono />
  <Field label="Signature Alg" value={signatureAlgorithmName(cert.signatureAlgorithm)} />
</Section>

{#if cert.issuer}
  <Section title="Issuer" accent="cyan">
    <DNView dn={cert.issuer} />
  </Section>
{/if}

{#if cert.validity}
  <Section title="Validity" accent="cyan">
    <Field label="Not Before" value={formatTimestamp(cert.validity.notBefore)} />
    <Field label="Not After" value={formatTimestamp(cert.validity.notAfter)} />
  </Section>
{/if}

{#if cert.holder}
  <Section title="Holder" accent="cyan">
    {#if cert.holder.entityName}
      <DNView dn={cert.holder.entityName} />
    {/if}
    {#if cert.holder.baseCertificateIssuer}
      <Field label="Base Cert Issuer" value="Present" />
    {/if}
  </Section>
{/if}

{#if cert.attributes.length > 0}
  <Section title="Attributes ({cert.attributes.length})" accent="cyan">
    {#each cert.attributes as attr}
      <Field label="Type" value={oidName(attr.type?.dotNotation ?? '')} mono />
    {/each}
  </Section>
{/if}

<Section title="Signature" accent="cyan" defaultOpen={false}>
  <ByteDisplay bytes={cert.signature} />
</Section>
