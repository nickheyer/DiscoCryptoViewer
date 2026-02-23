<script lang="ts">
  import type { JSONWebKey } from '../../proto/discocrypto/v1/jwk_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { hexColonFormat, bytesToBase64 } from '../../utils/format';

  let { jwk }: { jwk: JSONWebKey } = $props();
</script>

<Section title="JSON Web Key" accent="yellow">
  <Field label="Key Type" value={jwk.kty} />
  {#if jwk.use}
    <Field label="Use" value={jwk.use} />
  {/if}
  {#if jwk.alg}
    <Field label="Algorithm" value={jwk.alg} />
  {/if}
  {#if jwk.kid}
    <Field label="Key ID" value={jwk.kid} mono />
  {/if}
  <Field label="Private Key" value={jwk.isPrivate ? 'Yes' : 'No'} />
  {#if jwk.keyOps.length > 0}
    <div class="dc-field">
      <span class="dc-field-label">Key Ops</span>
      <span class="dc-field-value">
        <div class="dc-tags">
          {#each jwk.keyOps as op}
            <Badge text={op} color="yellow" />
          {/each}
        </div>
      </span>
    </div>
  {/if}
</Section>

{#if jwk.keyData.case === 'rsa' && jwk.keyData.value}
  <Section title="RSA Key Data" accent="yellow" defaultOpen={false}>
    <Field label="Modulus (n)" value={jwk.keyData.value.n.length > 0 ? `${jwk.keyData.value.n.length} bytes` : 'N/A'} />
    <Field label="Exponent (e)" value={jwk.keyData.value.e.length > 0 ? bytesToBase64(jwk.keyData.value.e) : 'N/A'} mono />
    {#if jwk.keyData.value.d.length > 0}
      <Field label="Private (d)" value="Present (redacted)" />
    {/if}
  </Section>
{:else if jwk.keyData.case === 'ec' && jwk.keyData.value}
  <Section title="EC Key Data" accent="yellow" defaultOpen={false}>
    <Field label="Curve" value={jwk.keyData.value.crv} />
    <Field label="X" value={jwk.keyData.value.x.length > 0 ? bytesToBase64(jwk.keyData.value.x) : 'N/A'} mono />
    <Field label="Y" value={jwk.keyData.value.y.length > 0 ? bytesToBase64(jwk.keyData.value.y) : 'N/A'} mono />
    {#if jwk.keyData.value.d.length > 0}
      <Field label="Private (d)" value="Present (redacted)" />
    {/if}
  </Section>
{:else if jwk.keyData.case === 'okp' && jwk.keyData.value}
  <Section title="OKP Key Data" accent="yellow" defaultOpen={false}>
    <Field label="Curve" value={jwk.keyData.value.crv} />
    <Field label="X" value={jwk.keyData.value.x.length > 0 ? bytesToBase64(jwk.keyData.value.x) : 'N/A'} mono />
    {#if jwk.keyData.value.d.length > 0}
      <Field label="Private (d)" value="Present (redacted)" />
    {/if}
  </Section>
{:else if jwk.keyData.case === 'oct' && jwk.keyData.value}
  <Section title="Symmetric Key" accent="yellow" defaultOpen={false}>
    <Field label="Key (k)" value="Present (redacted)" />
  </Section>
{/if}

{#if jwk.x5c.length > 0}
  <Section title="X.509 Certificate Chain ({jwk.x5c.length})" accent="yellow" defaultOpen={false}>
    {#each jwk.x5c as cert, i}
      <Field label="Cert {i + 1}" value="{cert.length} bytes" />
    {/each}
  </Section>
{/if}

{#if jwk.x5t.length > 0}
  <Section title="X.509 Thumbprint" accent="yellow" defaultOpen={false}>
    <Field label="x5t" value={hexColonFormat(jwk.x5t)} mono />
    {#if jwk.x5tS256.length > 0}
      <Field label="x5t#S256" value={hexColonFormat(jwk.x5tS256)} mono />
    {/if}
  </Section>
{/if}
