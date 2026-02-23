<script lang="ts">
  import type { PGPPrivateKey } from '../../proto/discocrypto/v1/pgp_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import {
    pgpKeyAlgorithmName, pgpSymmetricAlgorithmName, formatTimestamp,
    pgpKeyFlagName, hashAlgorithmName,
  } from '../../utils/format';

  let { key }: { key: PGPPrivateKey } = $props();
</script>

{#if key.encrypted}
  <div class="dc-encrypted">Encrypted PGP Private Key</div>
{/if}

<Section title="PGP Private Key" accent="orange">
  <Field label="Encrypted" value={key.encrypted ? 'Yes' : 'No'} />
  {#if key.cipher}
    <Field label="Cipher" value={pgpSymmetricAlgorithmName(key.cipher)} />
  {/if}
  {#if key.s2k}
    <Field label="S2K Type" value={key.s2k.type.toString()} />
    <Field label="S2K Hash" value={hashAlgorithmName(key.s2k.hash)} />
    {#if key.s2k.count}
      <Field label="S2K Count" value={key.s2k.count.toString()} />
    {/if}
  {/if}
</Section>

{#if key.publicKey}
  <Section title="Associated Public Key" accent="orange">
    <Field label="Key ID" value={key.publicKey.keyId} mono />
    <Field label="Fingerprint" value={key.publicKey.fingerprint} mono />
    <Field label="Key Size" value="{key.publicKey.keySizeBits} bits" />
    {#if key.publicKey.primaryKey}
      <Field label="Algorithm" value={pgpKeyAlgorithmName(key.publicKey.primaryKey.algorithm)} />
      <Field label="Created" value={formatTimestamp(key.publicKey.primaryKey.creationTime)} />
    {/if}
  </Section>

  {#if key.publicKey.userIds.length > 0}
    <Section title="User IDs" accent="orange">
      {#each key.publicKey.userIds as uid}
        <div style="padding: 4px 0">
          <span style="font-weight: 600">{uid.id}</span>
        </div>
      {/each}
    </Section>
  {/if}

  {#if key.publicKey.subkeys.length > 0}
    <Section title="Subkeys ({key.publicKey.subkeys.length})" accent="orange" defaultOpen={false}>
      {#each key.publicKey.subkeys as sub, i}
        <div style="margin-bottom: 4px; padding: 4px 6px; background: var(--dc-surface-1); border-radius: 4px; border: 1px solid var(--dc-border)">
          {#if sub.keyData}
            <Field label="Subkey {i + 1}" value="{pgpKeyAlgorithmName(sub.keyData.algorithm)} ({sub.keyData.keySizeBits} bits)" />
          {/if}
          {#if sub.keyFlags.length > 0}
            <div class="dc-tags" style="margin-top: 2px">
              {#each sub.keyFlags as flag}
                <Badge text={pgpKeyFlagName(flag)} color="orange" />
              {/each}
            </div>
          {/if}
        </div>
      {/each}
    </Section>
  {/if}
{/if}
