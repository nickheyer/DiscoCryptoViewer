<script lang="ts">
    import { onMount } from 'svelte';
    import type { CertInfo, MessageFromExtension } from './lib/types';
    import CertCard from './lib/CertCard.svelte';
    import "./app.css"

    let certs = $state<CertInfo[]>([]);
    let fileName = $state('');
    let error = $state('');
    let loading = $state(true);

    onMount(() => {
        window.addEventListener('message', (event: MessageEvent<MessageFromExtension>) => {
            const msg = event.data;
            if (msg.type === 'certs') {
                certs = msg.certs;
                fileName = msg.fileName;
                loading = false;
            } else if (msg.type === 'error') {
                error = msg.message;
                loading = false;
            }
        });
    });
</script>

<main>
    {#if loading}
        <div class="loading">Loading certificate data…</div>
    {:else if error}
        <div class="error">
            <h2>Failed to parse file</h2>
            <p>{error}</p>
        </div>
    {:else}
        <div class="header">
            <h1>🔐 {fileName}</h1>
            <span class="subtitle">{certs.length} certificate{certs.length !== 1 ? 's' : ''} found</span>
        </div>

        {#each certs as cert, i}
            <CertCard {cert} index={i} total={certs.length} />
        {/each}
    {/if}
</main>
