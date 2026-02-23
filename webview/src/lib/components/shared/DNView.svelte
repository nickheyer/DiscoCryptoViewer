<script lang="ts">
  import type { DistinguishedName } from '../../proto/discocrypto/v1/common_pb';

  let { dn }: { dn?: DistinguishedName } = $props();
</script>

{#if dn}
  <div class="dc-dn-grid">
    {#if dn.commonName}
      <span class="dc-dn-label">CN</span>
      <span class="dc-dn-value">{dn.commonName}</span>
    {/if}
    {#each dn.organization as org}
      <span class="dc-dn-label">O</span>
      <span class="dc-dn-value">{org}</span>
    {/each}
    {#each dn.organizationalUnit as ou}
      <span class="dc-dn-label">OU</span>
      <span class="dc-dn-value">{ou}</span>
    {/each}
    {#each dn.locality as loc}
      <span class="dc-dn-label">L</span>
      <span class="dc-dn-value">{loc}</span>
    {/each}
    {#each dn.province as prov}
      <span class="dc-dn-label">ST</span>
      <span class="dc-dn-value">{prov}</span>
    {/each}
    {#each dn.country as c}
      <span class="dc-dn-label">C</span>
      <span class="dc-dn-value">{c}</span>
    {/each}
    {#each dn.streetAddress as addr}
      <span class="dc-dn-label">STREET</span>
      <span class="dc-dn-value">{addr}</span>
    {/each}
    {#each dn.postalCode as pc}
      <span class="dc-dn-label">POSTAL</span>
      <span class="dc-dn-value">{pc}</span>
    {/each}
    {#if dn.serialNumber}
      <span class="dc-dn-label">SERIAL</span>
      <span class="dc-dn-value">{dn.serialNumber}</span>
    {/if}
    {#each dn.extraNames as extra}
      <span class="dc-dn-label">{extra.type?.dotNotation ?? '?'}</span>
      <span class="dc-dn-value">{extra.value}</span>
    {/each}
  </div>
{/if}
