<script lang="ts">
  import type { TimestampResponse } from '../../proto/discocrypto/v1/pkcs_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { formatTimestamp, bigIntToDecimal, oidName, hexColonFormat } from '../../utils/format';

  let { response }: { response: TimestampResponse } = $props();
</script>

<Section title="Timestamp Response" accent="purple">
  <Field label="Status" value={response.status.toString()} />
  {#if response.statusString}
    <Field label="Status String" value={response.statusString} />
  {/if}
</Section>

{#if response.tokenInfo}
  {@const ti = response.tokenInfo}
  <Section title="Token Info" accent="purple">
    <Field label="Version" value={ti.version.toString()} />
    {#if ti.policy}
      <Field label="Policy" value={oidName(ti.policy.dotNotation)} mono />
    {/if}
    {#if ti.messageImprintAlgorithm}
      <Field label="Hash Algorithm" value={oidName(ti.messageImprintAlgorithm.algorithm?.dotNotation ?? '')} />
    {/if}
    {#if ti.messageImprint.length > 0}
      <Field label="Message Imprint" value={hexColonFormat(ti.messageImprint)} mono />
    {/if}
    {#if ti.serialNumber}
      <Field label="Serial Number" value={bigIntToDecimal(ti.serialNumber)} mono />
    {/if}
    <Field label="Gen Time" value={formatTimestamp(ti.genTime)} />
    {#if ti.tsa}
      <Field label="TSA" value="Present" />
    {/if}
  </Section>
{/if}

{#if response.raw.length > 0}
  <Section title="Raw Data" accent="purple" defaultOpen={false}>
    <ByteDisplay bytes={response.raw} />
  </Section>
{/if}
