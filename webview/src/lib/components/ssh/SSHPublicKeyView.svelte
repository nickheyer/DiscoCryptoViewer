<script lang="ts">
  import type { SSHPublicKey } from '../../proto/discocrypto/v1/ssh_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { publicKeyAlgorithmName } from '../../utils/format';

  let { key }: { key: SSHPublicKey } = $props();
</script>

<Section title="SSH Public Key" accent="green">
  <Field label="Key Type" value={key.keyType} />
  {#if key.comment}
    <Field label="Comment" value={key.comment} />
  {/if}
  {#if key.fingerprintSha256}
    <Field label="SHA-256" value={key.fingerprintSha256} mono />
  {/if}
  {#if key.fingerprintMd5}
    <Field label="MD5" value={key.fingerprintMd5} mono />
  {/if}
</Section>

{#if key.publicKey}
  <Section title="Public Key Details" accent="green">
    <Field label="Algorithm" value={publicKeyAlgorithmName(key.publicKey.algorithm)} />
  </Section>
{/if}

{#if key.raw.length > 0}
  <Section title="Raw Data" accent="green" defaultOpen={false}>
    <ByteDisplay bytes={key.raw} />
  </Section>
{/if}
