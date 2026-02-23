<script lang="ts">
  import type { PublicKey } from '../../proto/discocrypto/v1/keys_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import FingerprintView from '../shared/FingerprintView.svelte';
  import { publicKeyAlgorithmName, namedCurveName, formatBigInt } from '../../utils/format';

  let { key }: { key: PublicKey } = $props();
</script>

<Section title="Public Key Info" accent="magenta">
  <Field label="Algorithm" value={publicKeyAlgorithmName(key.algorithm)} />

  {#if key.key.case === 'rsa' && key.key.value}
    <Field label="Key Size" value="{key.key.value.keySizeBits} bits" />
    <Field label="Exponent" value={key.key.value.e.toString()} />
  {:else if key.key.case === 'ecdsa' && key.key.value}
    <Field label="Curve" value={namedCurveName(key.key.value.curve)} />
    <Field label="Key Size" value="{key.key.value.keySizeBits} bits" />
  {:else if key.key.case === 'ed25519' && key.key.value}
    <Field label="Key Size" value="256 bits" />
  {:else if key.key.case === 'dsa' && key.key.value}
    <Field label="Key Size" value="{key.key.value.keySizeBits} bits" />
  {:else if key.key.case === 'ecdh' && key.key.value}
    <Field label="Curve" value={namedCurveName(key.key.value.curve)} />
  {/if}
</Section>

{#if key.key.case === 'rsa' && key.key.value?.n}
  <Section title="RSA Modulus" accent="magenta" defaultOpen={false}>
    <ByteDisplay bytes={key.key.value.n.value} />
  </Section>
{/if}

{#if key.key.case === 'ecdsa' && key.key.value}
  <Section title="EC Point" accent="magenta" defaultOpen={false}>
    {#if key.key.value.x}
      <ByteDisplay bytes={key.key.value.x.value} label="X" />
    {/if}
    {#if key.key.value.y}
      <ByteDisplay bytes={key.key.value.y.value} label="Y" />
    {/if}
  </Section>
{/if}

{#if key.key.case === 'ed25519' && key.key.value}
  <Section title="Key Data" accent="magenta" defaultOpen={false}>
    <ByteDisplay bytes={key.key.value.keyData} />
  </Section>
{/if}

{#if key.key.case === 'ecdh' && key.key.value}
  <Section title="Key Data" accent="magenta" defaultOpen={false}>
    <ByteDisplay bytes={key.key.value.keyData} />
  </Section>
{/if}

<Section title="Fingerprints" accent="magenta" defaultOpen={false}>
  <FingerprintView fingerprints={key.fingerprints} />
</Section>
