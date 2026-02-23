<script lang="ts">
  let { text, color = 'cyan' }: {
    text: string;
    color?: string;
  } = $props();
</script>

<span class="dc-badge accent-{color}">{text}</span>
