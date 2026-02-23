<script lang="ts">
  import type { OCSPRequest } from '../../proto/discocrypto/v1/ocsp_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { hashAlgorithmName, hexColonFormat, bigIntToDecimal } from '../../utils/format';

  let { request }: { request: OCSPRequest } = $props();
</script>

<Section title="OCSP Request" accent="red">
  <Field label="Hash Algorithm" value={hashAlgorithmName(request.hashAlgorithm)} />
  {#if request.serialNumber}
    <Field label="Serial Number" value={bigIntToDecimal(request.serialNumber)} mono />
  {/if}
</Section>

{#if request.issuerNameHash.length > 0}
  <Section title="Issuer Name Hash" accent="red" defaultOpen={false}>
    <div class="dc-fingerprint">{hexColonFormat(request.issuerNameHash)}</div>
  </Section>
{/if}

{#if request.issuerKeyHash.length > 0}
  <Section title="Issuer Key Hash" accent="red" defaultOpen={false}>
    <div class="dc-fingerprint">{hexColonFormat(request.issuerKeyHash)}</div>
  </Section>
{/if}

{#if request.raw.length > 0}
  <Section title="Raw Data" accent="red" defaultOpen={false}>
    <ByteDisplay bytes={request.raw} />
  </Section>
{/if}
