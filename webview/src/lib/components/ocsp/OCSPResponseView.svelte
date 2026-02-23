<script lang="ts">
  import type { OCSPResponse } from '../../proto/discocrypto/v1/ocsp_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import {
    ocspResponseStatusName, ocspCertStatusName, hashAlgorithmName,
    signatureAlgorithmName, formatTimestamp, hexColonFormat,
    bigIntToDecimal, revocationReasonName,
  } from '../../utils/format';

  let { response }: { response: OCSPResponse } = $props();
</script>

<Section title="OCSP Response" accent="red">
  <Field label="Status" value={ocspResponseStatusName(response.status)} />
  {#if response.status === 0}
    <Badge text="Successful" color="green" />
  {:else}
    <Badge text={ocspResponseStatusName(response.status)} color="red" />
  {/if}
</Section>

{#if response.response}
  {@const basic = response.response}

  <Section title="Response Details" accent="red">
    <Field label="Produced At" value={formatTimestamp(basic.producedAt)} />
    <Field label="Signature Alg" value={signatureAlgorithmName(basic.signatureAlgorithm)} />
    {#if basic.responderId.case === 'responderName'}
      <Field label="Responder" value="By Name" />
    {:else if basic.responderId.case === 'responderKeyHash'}
      <Field label="Responder Key" value={hexColonFormat(basic.responderId.value)} mono />
    {/if}
    <Field label="Certificates" value={basic.certificates.length.toString()} />
  </Section>

  {#each basic.responses as sr, i}
    <Section title="Certificate Status {i + 1}" accent="red" defaultOpen={i === 0}>
      <Field label="Hash Algorithm" value={hashAlgorithmName(sr.hashAlgorithm)} />
      {#if sr.serialNumber}
        <Field label="Serial Number" value={bigIntToDecimal(sr.serialNumber)} mono />
      {/if}
      <div style="margin: 4px 0">
        {#if sr.certStatus === 1}
          <Badge text="Good" color="green" />
        {:else if sr.certStatus === 2}
          <Badge text="Revoked" color="red" />
        {:else}
          <Badge text="Unknown" color="yellow" />
        {/if}
      </div>
      <Field label="This Update" value={formatTimestamp(sr.thisUpdate)} />
      <Field label="Next Update" value={formatTimestamp(sr.nextUpdate)} />
      {#if sr.certStatus === 2 && sr.revocationTime}
        <Field label="Revoked At" value={formatTimestamp(sr.revocationTime)} />
        <Field label="Reason" value={revocationReasonName(sr.revocationReason)} />
      {/if}
    </Section>
  {/each}

  {#if basic.signature.length > 0}
    <Section title="Signature" accent="red" defaultOpen={false}>
      <ByteDisplay bytes={basic.signature} />
    </Section>
  {/if}
{/if}
