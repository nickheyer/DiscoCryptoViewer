<script lang="ts">
  import type { CertificateRequest } from '../../proto/discocrypto/v1/x509_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import DNView from '../shared/DNView.svelte';
  import FingerprintView from '../shared/FingerprintView.svelte';
  import {
    signatureAlgorithmName, publicKeyAlgorithmName, formatIpAddress, oidName,
  } from '../../utils/format';

  let { csr }: { csr: CertificateRequest } = $props();
</script>

<Section title="Subject" accent="cyan">
  <DNView dn={csr.subject} />
</Section>

<Section title="Details" accent="cyan">
  <Field label="Version" value="v{csr.version}" />
  <Field label="Signature Alg" value={signatureAlgorithmName(csr.signatureAlgorithm)} />
  <Field label="Public Key Alg" value={publicKeyAlgorithmName(csr.publicKeyAlgorithm)} />
</Section>

{#if csr.subjectAltNames}
  {@const san = csr.subjectAltNames}
  {#if san.dnsNames.length > 0 || san.emailAddresses.length > 0 || san.ipAddresses.length > 0 || san.uris.length > 0}
    <Section title="Subject Alternative Names" accent="cyan">
      <div class="dc-tags">
        {#each san.dnsNames as dns}
          <span class="dc-tag">DNS: {dns}</span>
        {/each}
        {#each san.emailAddresses as email}
          <span class="dc-tag">Email: {email}</span>
        {/each}
        {#each san.ipAddresses as ip}
          <span class="dc-tag">IP: {formatIpAddress(ip)}</span>
        {/each}
        {#each san.uris as uri}
          <span class="dc-tag">URI: {uri}</span>
        {/each}
      </div>
    </Section>
  {/if}
{/if}

{#if csr.extensions.length > 0}
  <Section title="Extensions ({csr.extensions.length})" accent="cyan" defaultOpen={false}>
    {#each csr.extensions as ext}
      <div class="dc-field">
        <span class="dc-field-label">{oidName(ext.id?.dotNotation ?? '')}</span>
        <span class="dc-field-value">
          {#if ext.critical}<Badge text="Critical" color="red" />{/if}
          <span class="mono" style="font-size: 0.85em; color: var(--dc-text-dim)">{ext.id?.dotNotation ?? ''}</span>
        </span>
      </div>
    {/each}
  </Section>
{/if}

<Section title="Fingerprints" accent="cyan" defaultOpen={false}>
  <FingerprintView fingerprints={csr.fingerprints} />
</Section>

<Section title="Signature" accent="cyan" defaultOpen={false}>
  <ByteDisplay bytes={csr.signature} />
</Section>
