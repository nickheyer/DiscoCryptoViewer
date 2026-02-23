<script lang="ts">
  import type { Fingerprints } from '../../proto/discocrypto/v1/common_pb';
  import { hexColonFormat } from '../../utils/format';

  let { fingerprints }: { fingerprints?: Fingerprints } = $props();
</script>

{#if fingerprints}
  {#if fingerprints.sha256.length > 0}
    <div class="dc-field">
      <span class="dc-field-label">SHA-256</span>
      <span class="dc-field-value mono dc-fingerprint">{hexColonFormat(fingerprints.sha256)}</span>
    </div>
  {/if}
  {#if fingerprints.sha1.length > 0}
    <div class="dc-field">
      <span class="dc-field-label">SHA-1</span>
      <span class="dc-field-value mono dc-fingerprint">{hexColonFormat(fingerprints.sha1)}</span>
    </div>
  {/if}
  {#if fingerprints.md5.length > 0}
    <div class="dc-field">
      <span class="dc-field-label">MD5</span>
      <span class="dc-field-value mono dc-fingerprint">{hexColonFormat(fingerprints.md5)}</span>
    </div>
  {/if}
{/if}
