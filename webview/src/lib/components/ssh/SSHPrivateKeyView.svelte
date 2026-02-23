<script lang="ts">
  import type { SSHPrivateKey } from '../../proto/discocrypto/v1/ssh_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import { publicKeyAlgorithmName } from '../../utils/format';

  let { key }: { key: SSHPrivateKey } = $props();
</script>

{#if key.encrypted}
  <div class="dc-encrypted">Encrypted SSH Private Key</div>
{/if}

<Section title="SSH Private Key" accent="green">
  <Field label="Key Type" value={key.keyType} />
  {#if key.comment}
    <Field label="Comment" value={key.comment} />
  {/if}
  <Field label="Cipher" value={key.cipherName || 'none'} />
  <Field label="KDF" value={key.kdfName || 'none'} />
  <Field label="Encrypted" value={key.encrypted ? 'Yes' : 'No'} />
</Section>

{#if key.publicKey}
  <Section title="Public Key" accent="green">
    <Field label="Key Type" value={key.publicKey.keyType} />
    {#if key.publicKey.fingerprintSha256}
      <Field label="SHA-256" value={key.publicKey.fingerprintSha256} mono />
    {/if}
  </Section>
{/if}

{#if key.privateKey}
  <Section title="Private Key" accent="green">
    <Field label="Algorithm" value={publicKeyAlgorithmName(key.privateKey.algorithm)} />
  </Section>
{/if}
