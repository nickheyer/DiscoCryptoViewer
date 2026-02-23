<script lang="ts">
  import type { PGPPublicKey } from '../../proto/discocrypto/v1/pgp_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import {
    pgpKeyAlgorithmName, formatTimestamp, pgpSignatureTypeName, pgpKeyFlagName,
  } from '../../utils/format';

  let { key }: { key: PGPPublicKey } = $props();
</script>

<Section title="PGP Public Key" accent="orange">
  <Field label="Key ID" value={key.keyId} mono />
  <Field label="Fingerprint" value={key.fingerprint} mono />
  <Field label="Key Size" value="{key.keySizeBits} bits" />
  {#if key.primaryKey}
    <Field label="Algorithm" value={pgpKeyAlgorithmName(key.primaryKey.algorithm)} />
    <Field label="Version" value="v{key.primaryKey.version}" />
    <Field label="Created" value={formatTimestamp(key.primaryKey.creationTime)} />
    {#if key.primaryKey.expirationTime}
      <Field label="Expires" value={formatTimestamp(key.primaryKey.expirationTime)} />
    {/if}
  {/if}
</Section>

{#if key.userIds.length > 0}
  <Section title="User IDs ({key.userIds.length})" accent="orange">
    {#each key.userIds as uid}
      <div style="margin-bottom: 6px; padding: 6px; background: var(--dc-surface-1); border-radius: 4px; border: 1px solid var(--dc-border)">
        <div style="font-weight: 600; margin-bottom: 2px">{uid.id}</div>
        {#if uid.name}
          <Field label="Name" value={uid.name} />
        {/if}
        {#if uid.email}
          <Field label="Email" value={uid.email} />
        {/if}
        {#if uid.comment}
          <Field label="Comment" value={uid.comment} />
        {/if}
      </div>
    {/each}
  </Section>
{/if}

{#if key.subkeys.length > 0}
  <Section title="Subkeys ({key.subkeys.length})" accent="orange" defaultOpen={false}>
    {#each key.subkeys as sub, i}
      <div style="margin-bottom: 6px; padding: 6px; background: var(--dc-surface-1); border-radius: 4px; border: 1px solid var(--dc-border)">
        <div style="display: flex; gap: 6px; align-items: center; margin-bottom: 4px">
          <Badge text="Subkey {i + 1}" color="orange" />
        </div>
        {#if sub.keyData}
          <Field label="Algorithm" value={pgpKeyAlgorithmName(sub.keyData.algorithm)} />
          <Field label="Key Size" value="{sub.keyData.keySizeBits} bits" />
          <Field label="Key ID" value={sub.keyData.keyId} mono />
          <Field label="Created" value={formatTimestamp(sub.keyData.creationTime)} />
        {/if}
        {#if sub.keyFlags.length > 0}
          <div class="dc-tags" style="margin-top: 4px">
            {#each sub.keyFlags as flag}
              <Badge text={pgpKeyFlagName(flag)} color="orange" />
            {/each}
          </div>
        {/if}
      </div>
    {/each}
  </Section>
{/if}

{#if key.signatures.length > 0}
  <Section title="Signatures ({key.signatures.length})" accent="orange" defaultOpen={false}>
    {#each key.signatures as sig, i}
      <div style="margin-bottom: 4px; padding: 4px 6px; background: var(--dc-surface-1); border-radius: 4px; border: 1px solid var(--dc-border)">
        <Field label="Type" value={pgpSignatureTypeName(sig.sigType)} />
        <Field label="Issuer Key ID" value={sig.issuerKeyId} mono />
        <Field label="Created" value={formatTimestamp(sig.creationTime)} />
      </div>
    {/each}
  </Section>
{/if}
