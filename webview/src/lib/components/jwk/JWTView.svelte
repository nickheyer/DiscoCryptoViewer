<script lang="ts">
  import type { JSONWebToken } from '../../proto/discocrypto/v1/jwk_pb';
  import Section from '../shared/Section.svelte';
  import Field from '../shared/Field.svelte';
  import Badge from '../shared/Badge.svelte';
  import ByteDisplay from '../shared/ByteDisplay.svelte';
  import { formatTimestamp } from '../../utils/format';

  let { jwt }: { jwt: JSONWebToken } = $props();
</script>

{#if jwt.header}
  <Section title="JOSE Header" accent="yellow">
    {#if jwt.header.alg}
      <Field label="Algorithm" value={jwt.header.alg} />
    {/if}
    {#if jwt.header.typ}
      <Field label="Type" value={jwt.header.typ} />
    {/if}
    {#if jwt.header.cty}
      <Field label="Content Type" value={jwt.header.cty} />
    {/if}
    {#if jwt.header.kid}
      <Field label="Key ID" value={jwt.header.kid} mono />
    {/if}
    {#if jwt.header.enc}
      <Field label="Encryption" value={jwt.header.enc} />
    {/if}
    {#if jwt.header.zip}
      <Field label="Compression" value={jwt.header.zip} />
    {/if}
    {#if Object.keys(jwt.header.extra).length > 0}
      {#each Object.entries(jwt.header.extra) as [k, v]}
        <Field label={k} value={v} />
      {/each}
    {/if}
  </Section>
{/if}

{#if jwt.claims}
  <Section title="Claims" accent="yellow">
    {#if jwt.claims.issuer}
      <Field label="Issuer (iss)" value={jwt.claims.issuer} />
    {/if}
    {#if jwt.claims.subject}
      <Field label="Subject (sub)" value={jwt.claims.subject} />
    {/if}
    {#if jwt.claims.audience.length > 0}
      <div class="dc-field">
        <span class="dc-field-label">Audience (aud)</span>
        <span class="dc-field-value">
          <div class="dc-tags">
            {#each jwt.claims.audience as aud}
              <span class="dc-tag">{aud}</span>
            {/each}
          </div>
        </span>
      </div>
    {/if}
    <Field label="Expiration (exp)" value={formatTimestamp(jwt.claims.expiration)} />
    <Field label="Not Before (nbf)" value={formatTimestamp(jwt.claims.notBefore)} />
    <Field label="Issued At (iat)" value={formatTimestamp(jwt.claims.issuedAt)} />
    {#if jwt.claims.jwtId}
      <Field label="JWT ID (jti)" value={jwt.claims.jwtId} mono />
    {/if}
    {#if Object.keys(jwt.claims.extra).length > 0}
      {#each Object.entries(jwt.claims.extra) as [k, v]}
        <Field label={k} value={v} />
      {/each}
    {/if}
  </Section>
{/if}

{#if jwt.validation}
  <Section title="Validation" accent="yellow">
    <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 4px">
      {#if jwt.validation.signatureValid}
        <Badge text="Signature Valid" color="green" />
      {/if}
      {#if jwt.validation.expired}
        <Badge text="Expired" color="red" />
      {/if}
      {#if jwt.validation.notYetValid}
        <Badge text="Not Yet Valid" color="yellow" />
      {/if}
    </div>
    {#if jwt.validation.errors.length > 0}
      {#each jwt.validation.errors as err}
        <div style="color: var(--dc-red); font-size: 0.88em; padding: 2px 0">{err}</div>
      {/each}
    {/if}
  </Section>
{/if}

{#if jwt.signature.length > 0}
  <Section title="Signature" accent="yellow" defaultOpen={false}>
    <ByteDisplay bytes={jwt.signature} />
  </Section>
{/if}
