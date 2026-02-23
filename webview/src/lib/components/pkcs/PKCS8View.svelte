<script lang="ts">
  import type { PKCS8PrivateKeyInfo, PKCS8EncryptedPrivateKeyInfo } from '../../proto/discocrypto/v1/pkcs_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { oidName, publicKeyAlgorithmName } from '../../utils/format';

  let { info, encrypted }: {
    info?: PKCS8PrivateKeyInfo;
    encrypted?: PKCS8EncryptedPrivateKeyInfo;
  } = $props();
</script>

{#if encrypted}
  <div class="dc-encrypted">Encrypted PKCS#8 Private Key</div>

  <Section title="Encryption" accent="blue">
    {#if encrypted.encryptionAlgorithm}
      <Field label="Algorithm" value={oidName(encrypted.encryptionAlgorithm.algorithm?.dotNotation ?? '')} mono />
    {/if}
    {#if encrypted.pbes2Params}
      {#if encrypted.pbes2Params.keyDerivationFunc}
        {#if encrypted.pbes2Params.keyDerivationFunc.prf}
          <Field label="KDF PRF" value={oidName(encrypted.pbes2Params.keyDerivationFunc.prf.algorithm?.dotNotation ?? '')} />
        {/if}
        <Field label="Iterations" value={encrypted.pbes2Params.keyDerivationFunc.iterationCount.toString()} />
      {/if}
      {#if encrypted.pbes2Params.encryptionScheme}
        <Field label="Cipher" value={oidName(encrypted.pbes2Params.encryptionScheme.algorithm?.dotNotation ?? '')} />
      {/if}
    {/if}
    <Field label="Encrypted Data" value="{encrypted.encryptedData.length} bytes" />
  </Section>
{/if}

{#if info}
  <Section title="PKCS#8 Private Key" accent="blue">
    <Field label="Version" value={info.version.toString()} />
    {#if info.algorithm}
      <Field label="Algorithm" value={oidName(info.algorithm.algorithm?.dotNotation ?? '')} mono />
    {/if}
    <Field label="Key Data" value="{info.privateKey.length} bytes" />
  </Section>

  {#if info.parsedKey}
    <Section title="Parsed Key" accent="blue">
      <Field label="Algorithm" value={publicKeyAlgorithmName(info.parsedKey.algorithm)} />
      <Field label="Encrypted" value={info.parsedKey.encrypted ? 'Yes' : 'No'} />
    </Section>
  {/if}
{/if}
