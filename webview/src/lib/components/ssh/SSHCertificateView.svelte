<script lang="ts">
  import type { SSHCertificate } from '../../proto/discocrypto/v1/ssh_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import {
    sshCertTypeName, publicKeyAlgorithmName, formatTimestamp, hexColonFormat,
  } from '../../utils/format';

  let { cert }: { cert: SSHCertificate } = $props();
</script>

<Section title="SSH Certificate" accent="green">
  <Field label="Type" value={sshCertTypeName(cert.certType)} />
  <Field label="Serial" value={cert.serial.toString()} mono />
  <Field label="Key ID" value={cert.keyId} />
  <Field label="Valid After" value={formatTimestamp(cert.validAfter)} />
  <Field label="Valid Before" value={formatTimestamp(cert.validBefore)} />
</Section>

{#if cert.validPrincipals.length > 0}
  <Section title="Principals ({cert.validPrincipals.length})" accent="green">
    <div class="dc-tags">
      {#each cert.validPrincipals as p}
        <span class="dc-tag">{p}</span>
      {/each}
    </div>
  </Section>
{/if}

{#if Object.keys(cert.criticalOptions).length > 0}
  <Section title="Critical Options" accent="green">
    <div class="dc-map">
      {#each Object.entries(cert.criticalOptions) as [k, v]}
        <div class="dc-map-entry">
          <span class="dc-map-key">{k}</span>
          <span class="dc-map-value">{v || '(empty)'}</span>
        </div>
      {/each}
    </div>
  </Section>
{/if}

{#if Object.keys(cert.extensions).length > 0}
  <Section title="Extensions" accent="green">
    <div class="dc-tags">
      {#each Object.keys(cert.extensions) as ext}
        <Badge text={ext} color="green" />
      {/each}
    </div>
  </Section>
{/if}

{#if cert.key}
  <Section title="Certificate Key" accent="green" defaultOpen={false}>
    <Field label="Key Type" value={cert.key.keyType} />
    {#if cert.key.fingerprintSha256}
      <Field label="SHA-256" value={cert.key.fingerprintSha256} mono />
    {/if}
  </Section>
{/if}

{#if cert.signatureKey}
  <Section title="Signing Key" accent="green" defaultOpen={false}>
    <Field label="Key Type" value={cert.signatureKey.keyType} />
    {#if cert.signatureKey.fingerprintSha256}
      <Field label="SHA-256" value={cert.signatureKey.fingerprintSha256} mono />
    {/if}
  </Section>
{/if}

{#if cert.nonce.length > 0}
  <Section title="Nonce" accent="green" defaultOpen={false}>
    <ByteDisplay bytes={cert.nonce} />
  </Section>
{/if}

<Section title="Signature" accent="green" defaultOpen={false}>
  <ByteDisplay bytes={cert.signature} />
</Section>
