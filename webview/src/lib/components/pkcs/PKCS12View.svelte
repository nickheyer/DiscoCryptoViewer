<script lang="ts">
  import type { PKCS12 } from '../../proto/discocrypto/v1/pkcs_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import CertificateView from '../x509/CertificateView.svelte';
  import {
    pkcs12BagTypeName, publicKeyAlgorithmName,
  } from '../../utils/format';

  let { p12 }: { p12: PKCS12 } = $props();
</script>

<Section title="PKCS#12 Archive" accent="blue">
  <Field label="Version" value={p12.version.toString()} />
  <Field label="Safe Bags" value={p12.safeBags.length.toString()} />
  <Field label="Certificates" value={p12.certificates.length.toString()} />
  <Field label="CA Certificates" value={p12.caCertificates.length.toString()} />
  <Field label="Private Key" value={p12.privateKey ? 'Present' : 'None'} />
</Section>

{#if p12.safeBags.length > 0}
  <Section title="Safe Bags ({p12.safeBags.length})" accent="blue" defaultOpen={false}>
    {#each p12.safeBags as bag, i}
      <div style="margin-bottom: 6px; padding: 6px; background: var(--dc-surface-1); border-radius: 4px; border: 1px solid var(--dc-border)">
        <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 4px">
          <Badge text="Bag {i + 1}" color="blue" />
          <span style="font-size: 0.88em">{pkcs12BagTypeName(bag.bagType)}</span>
        </div>
        {#if bag.bagId}
          <Field label="Bag ID" value={bag.bagId.dotNotation} mono />
        {/if}
      </div>
    {/each}
  </Section>
{/if}

{#each p12.certificates as cert, i}
  <div style="margin-top: 16px; padding-top: 16px; border-top: 2px solid var(--dc-border)">
    <div style="margin-bottom: 8px; font-size: 0.82em; color: var(--dc-text-dim); text-transform: uppercase; letter-spacing: 0.04em">
      Certificate {i + 1} of {p12.certificates.length}
    </div>
    <CertificateView {cert} />
  </div>
{/each}

{#if p12.privateKey}
  <Section title="Private Key" accent="magenta">
    <Field label="Algorithm" value={publicKeyAlgorithmName(p12.privateKey.algorithm)} />
    <Field label="Encrypted" value={p12.privateKey.encrypted ? 'Yes' : 'No'} />
  </Section>
{/if}
