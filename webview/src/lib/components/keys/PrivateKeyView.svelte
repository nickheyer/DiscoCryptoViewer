<script lang="ts">
  import type { PrivateKey } from '../../proto/discocrypto/v1/keys_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import { publicKeyAlgorithmName, namedCurveName } from '../../utils/format';

  let { key }: { key: PrivateKey } = $props();
</script>

{#if key.encrypted}
  <div class="dc-encrypted">Encrypted Private Key</div>
{/if}

<Section title="Private Key Info" accent="magenta">
  <Field label="Algorithm" value={publicKeyAlgorithmName(key.algorithm)} />

  {#if key.key.case === 'rsa' && key.key.value}
    {#if key.key.value.publicKey}
      <Field label="Key Size" value="{key.key.value.publicKey.keySizeBits} bits" />
      <Field label="Exponent" value={key.key.value.publicKey.e.toString()} />
    {/if}
    <Field label="Primes" value={key.key.value.primes.length.toString()} />
    <Field label="Encrypted" value={key.key.value.encrypted ? 'Yes' : 'No'} />
  {:else if key.key.case === 'ecdsa' && key.key.value}
    {#if key.key.value.publicKey}
      <Field label="Curve" value={namedCurveName(key.key.value.publicKey.curve)} />
      <Field label="Key Size" value="{key.key.value.publicKey.keySizeBits} bits" />
    {/if}
    <Field label="Encrypted" value={key.key.value.encrypted ? 'Yes' : 'No'} />
  {:else if key.key.case === 'ed25519' && key.key.value}
    <Field label="Key Size" value="256 bits" />
    <Field label="Encrypted" value={key.key.value.encrypted ? 'Yes' : 'No'} />
  {:else if key.key.case === 'dsa' && key.key.value}
    {#if key.key.value.publicKey}
      <Field label="Key Size" value="{key.key.value.publicKey.keySizeBits} bits" />
    {/if}
    <Field label="Encrypted" value={key.key.value.encrypted ? 'Yes' : 'No'} />
  {:else if key.key.case === 'ecdh' && key.key.value}
    {#if key.key.value.publicKey}
      <Field label="Curve" value={namedCurveName(key.key.value.publicKey.curve)} />
    {/if}
    <Field label="Encrypted" value={key.key.value.encrypted ? 'Yes' : 'No'} />
  {/if}
</Section>
