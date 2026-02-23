<script lang="ts">
  import type { CertificateRevocationList } from '../../proto/discocrypto/v1/x509_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import DNView from '../shared/DNView.svelte';
  import FingerprintView from '../shared/FingerprintView.svelte';
  import {
    signatureAlgorithmName, formatTimestamp, bigIntToDecimal,
    hexColonFormat, revocationReasonName,
  } from '../../utils/format';

  let { crl }: { crl: CertificateRevocationList } = $props();
</script>

<Section title="Issuer" accent="cyan">
  <DNView dn={crl.issuer} />
</Section>

<Section title="Details" accent="cyan">
  <Field label="Version" value="v{crl.version}" />
  <Field label="Signature Alg" value={signatureAlgorithmName(crl.signatureAlgorithm)} />
  <Field label="This Update" value={formatTimestamp(crl.thisUpdate)} />
  <Field label="Next Update" value={formatTimestamp(crl.nextUpdate)} />
  {#if crl.number}
    <Field label="CRL Number" value={bigIntToDecimal(crl.number)} mono />
  {/if}
</Section>

{#if crl.revokedCertificates.length > 0}
  <Section title="Revoked Certificates ({crl.revokedCertificates.length})" accent="red">
    {#each crl.revokedCertificates as entry}
      <div class="dc-field">
        <span class="dc-field-label mono">{bigIntToDecimal(entry.serialNumber)}</span>
        <span class="dc-field-value">
          {formatTimestamp(entry.revocationTime)}
          {#if entry.reason}
            <Badge text={revocationReasonName(entry.reason)} color="red" />
          {/if}
        </span>
      </div>
    {/each}
  </Section>
{:else}
  <Section title="Revoked Certificates" accent="cyan">
    <div style="color: var(--dc-text-dim); font-size: 0.9em">No revoked certificates</div>
  </Section>
{/if}

{#if crl.authorityKeyId.length > 0}
  <Section title="Authority Key ID" accent="cyan" defaultOpen={false}>
    <div class="dc-fingerprint">{hexColonFormat(crl.authorityKeyId)}</div>
  </Section>
{/if}

<Section title="Fingerprints" accent="cyan" defaultOpen={false}>
  <FingerprintView fingerprints={crl.fingerprints} />
</Section>

<Section title="Signature" accent="cyan" defaultOpen={false}>
  <ByteDisplay bytes={crl.signature} />
</Section>
