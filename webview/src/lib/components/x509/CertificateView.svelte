<script lang="ts">
  import type { Certificate } from '../../proto/discocrypto/v1/x509_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import DNView from '../shared/DNView.svelte';
  import FingerprintView from '../shared/FingerprintView.svelte';
  import {
    signatureAlgorithmName, publicKeyAlgorithmName, keyUsageName,
    extKeyUsageName, formatTimestamp, hexColonFormat, isExpired,
    isNotYetValid, bigIntToDecimal, oidName, formatIpAddress,
  } from '../../utils/format';

  let { cert }: { cert: Certificate } = $props();

  let validityStatus = $derived(
    isExpired(cert.validity?.notAfter) ? 'expired'
    : isNotYetValid(cert.validity?.notBefore) ? 'not-yet-valid'
    : 'valid'
  );
</script>

<Section title="Subject" accent="cyan">
  <DNView dn={cert.subject} />
</Section>

<Section title="Issuer" accent="cyan">
  <DNView dn={cert.issuer} />
  {#if cert.isSelfSigned}
    <div style="margin-top: 4px"><Badge text="Self-Signed" color="yellow" /></div>
  {/if}
</Section>

<Section title="Validity" accent="cyan">
  <Field label="Not Before" value={formatTimestamp(cert.validity?.notBefore)} />
  <Field label="Not After" value={formatTimestamp(cert.validity?.notAfter)} />
  <div style="margin-top: 4px">
    {#if validityStatus === 'expired'}
      <Badge text="Expired" color="red" />
    {:else if validityStatus === 'not-yet-valid'}
      <Badge text="Not Yet Valid" color="yellow" />
    {:else}
      <Badge text="Valid" color="green" />
    {/if}
  </div>
</Section>

<Section title="Details" accent="cyan">
  <Field label="Version" value="v{cert.version}" />
  <Field label="Serial Number" value={bigIntToDecimal(cert.serialNumber)} mono />
  <Field label="Signature Alg" value={signatureAlgorithmName(cert.signatureAlgorithm)} />
  <Field label="Public Key Alg" value={publicKeyAlgorithmName(cert.publicKeyAlgorithm)} />
</Section>

{#if cert.keyUsage.length > 0}
  <Section title="Key Usage" accent="cyan">
    <div class="dc-tags">
      {#each cert.keyUsage as ku}
        <Badge text={keyUsageName(ku)} color="cyan" />
      {/each}
    </div>
  </Section>
{/if}

{#if cert.extKeyUsage.length > 0}
  <Section title="Extended Key Usage" accent="cyan">
    <div class="dc-tags">
      {#each cert.extKeyUsage as eku}
        <Badge text={extKeyUsageName(eku)} color="blue" />
      {/each}
    </div>
  </Section>
{/if}

{#if cert.subjectAltNames}
  {@const san = cert.subjectAltNames}
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

{#if cert.basicConstraints}
  <Section title="Basic Constraints" accent="cyan">
    <Field label="CA" value={cert.basicConstraints.isCa ? 'Yes' : 'No'} />
    {#if cert.basicConstraints.isCa && (cert.basicConstraints.maxPathLen > 0 || cert.basicConstraints.maxPathLenZero)}
      <Field label="Max Path Length" value={cert.basicConstraints.maxPathLen.toString()} />
    {/if}
  </Section>
{/if}

{#if cert.subjectKeyId.length > 0 || cert.authorityKeyId}
  <Section title="Key Identifiers" accent="cyan" defaultOpen={false}>
    {#if cert.subjectKeyId.length > 0}
      <Field label="Subject Key ID" value={hexColonFormat(cert.subjectKeyId)} mono />
    {/if}
    {#if cert.authorityKeyId?.keyId && cert.authorityKeyId.keyId.length > 0}
      <Field label="Authority Key ID" value={hexColonFormat(cert.authorityKeyId.keyId)} mono />
    {/if}
  </Section>
{/if}

{#if cert.authorityInfoAccess}
  {@const aia = cert.authorityInfoAccess}
  {#if aia.ocspServers.length > 0 || aia.issuingCertificateUrls.length > 0}
    <Section title="Authority Info Access" accent="cyan" defaultOpen={false}>
      {#each aia.ocspServers as url}
        <Field label="OCSP" value={url} />
      {/each}
      {#each aia.issuingCertificateUrls as url}
        <Field label="CA Issuer" value={url} />
      {/each}
    </Section>
  {/if}
{/if}

{#if cert.crlDistributionPoints.length > 0}
  <Section title="CRL Distribution Points" accent="cyan" defaultOpen={false}>
    {#each cert.crlDistributionPoints as dp}
      {#each dp.fullName as gn}
        {#if gn.name.case === 'uri'}
          <Field label="URI" value={gn.name.value} />
        {:else if gn.name.case === 'dnsName'}
          <Field label="DNS" value={gn.name.value} />
        {/if}
      {/each}
    {/each}
  </Section>
{/if}

{#if cert.certificatePolicies.length > 0}
  <Section title="Certificate Policies" accent="cyan" defaultOpen={false}>
    {#each cert.certificatePolicies as policy}
      <Field label="Policy OID" value={oidName(policy.policyIdentifier?.dotNotation ?? '')} mono />
      {#each policy.qualifiers as q}
        {#if q.cpsUri}
          <Field label="CPS URI" value={q.cpsUri} />
        {/if}
      {/each}
    {/each}
  </Section>
{/if}

{#if cert.signedCertificateTimestamps.length > 0}
  <Section title="SCTs" accent="cyan" defaultOpen={false}>
    {#each cert.signedCertificateTimestamps as sct, i}
      <Field label="SCT #{i + 1}" value={formatTimestamp(sct.timestamp)} />
    {/each}
  </Section>
{/if}

{#if cert.extensions.length > 0}
  <Section title="Extensions ({cert.extensions.length})" accent="cyan" defaultOpen={false}>
    {#each cert.extensions as ext}
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
  <FingerprintView fingerprints={cert.fingerprints} />
</Section>

<Section title="Signature" accent="cyan" defaultOpen={false}>
  <ByteDisplay bytes={cert.signature} />
</Section>
