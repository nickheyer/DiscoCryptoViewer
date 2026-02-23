<script lang="ts">
  let { label, value = '', mono = false }: {
    label: string;
    value?: string;
    mono?: boolean;
  } = $props();
</script>

{#if value}
  <div class="dc-field">
    <span class="dc-field-label">{label}</span>
    <span class="dc-field-value" class:mono>{value}</span>
  </div>
{/if}
