<script lang="ts">
  import type { PKCS7 } from '../../proto/discocrypto/v1/pkcs_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import DNView from '../shared/DNView.svelte';
  import CertificateView from '../x509/CertificateView.svelte';
  import {
    cmsContentTypeName, oidName, signatureAlgorithmName, hexColonFormat,
    bigIntToDecimal,
  } from '../../utils/format';

  let { pkcs7 }: { pkcs7: PKCS7 } = $props();
</script>

<Section title="PKCS#7 / CMS" accent="blue">
  <Field label="Content Type" value={cmsContentTypeName(pkcs7.contentType)} />
</Section>

{#if pkcs7.content.case === 'signedData' && pkcs7.content.value}
  {@const sd = pkcs7.content.value}
  <Section title="Signed Data" accent="blue">
    <Field label="Version" value={sd.version.toString()} />
    {#if sd.digestAlgorithms.length > 0}
      <div class="dc-field">
        <span class="dc-field-label">Digest Algs</span>
        <span class="dc-field-value">
          <div class="dc-tags">
            {#each sd.digestAlgorithms as alg}
              <Badge text={oidName(alg.algorithm?.dotNotation ?? '')} color="blue" />
            {/each}
          </div>
        </span>
      </div>
    {/if}
    <Field label="Certificates" value={sd.certificates.length.toString()} />
    <Field label="Signers" value={sd.signerInfos.length.toString()} />
  </Section>

  {#each sd.certificates as cert, i}
    <div style="margin-top: 16px; padding-top: 16px; border-top: 2px solid var(--dc-border)">
      <div style="margin-bottom: 8px; font-size: 0.82em; color: var(--dc-text-dim); text-transform: uppercase; letter-spacing: 0.04em">
        Certificate {i + 1} of {sd.certificates.length}
      </div>
      <CertificateView {cert} />
    </div>
  {/each}

  {#each sd.signerInfos as signer, i}
    <Section title="Signer {i + 1}" accent="blue" defaultOpen={false}>
      <Field label="Version" value={signer.version.toString()} />
      {#if signer.digestAlgorithm}
        <Field label="Digest Alg" value={oidName(signer.digestAlgorithm.algorithm?.dotNotation ?? '')} />
      {/if}
      {#if signer.signatureAlgorithm}
        <Field label="Signature Alg" value={oidName(signer.signatureAlgorithm.algorithm?.dotNotation ?? '')} />
      {/if}
      {#if signer.sid?.identifier.case === 'issuerAndSerial' && signer.sid.identifier.value}
        <Field label="Issuer Serial" value={bigIntToDecimal(signer.sid.identifier.value.serialNumber)} mono />
      {:else if signer.sid?.identifier.case === 'subjectKeyId'}
        <Field label="Subject Key ID" value={hexColonFormat(signer.sid.identifier.value)} mono />
      {/if}
      <ByteDisplay bytes={signer.signature} label="Signature" />
    </Section>
  {/each}

{:else if pkcs7.content.case === 'envelopedData' && pkcs7.content.value}
  {@const ed = pkcs7.content.value}
  <Section title="Enveloped Data" accent="blue">
    <Field label="Version" value={ed.version.toString()} />
    <Field label="Recipients" value={ed.recipientInfos.length.toString()} />
    {#if ed.encryptedContentInfo?.contentEncryptionAlgorithm}
      <Field label="Encryption Alg" value={oidName(ed.encryptedContentInfo.contentEncryptionAlgorithm.algorithm?.dotNotation ?? '')} />
    {/if}
  </Section>

{:else if pkcs7.content.case === 'encryptedData' && pkcs7.content.value}
  {@const enc = pkcs7.content.value}
  <Section title="Encrypted Data" accent="blue">
    <Field label="Version" value={enc.version.toString()} />
    {#if enc.encryptedContentInfo?.contentEncryptionAlgorithm}
      <Field label="Encryption Alg" value={oidName(enc.encryptedContentInfo.contentEncryptionAlgorithm.algorithm?.dotNotation ?? '')} />
    {/if}
  </Section>

{:else if pkcs7.content.case === 'rawData'}
  <Section title="Raw Data" accent="blue" defaultOpen={false}>
    <ByteDisplay bytes={pkcs7.content.value} />
  </Section>
{/if}
