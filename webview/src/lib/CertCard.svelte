<script lang="ts">
    import type { CertInfo } from './types';

    let { cert, index, total }: { cert: CertInfo; index: number; total: number } = $props();

    let expanded = $state(true);

    const label = $derived(total > 1 ? `Certificate ${index + 1} of ${total}` : 'Certificate Details');

    const isExpired = $derived(() => {
        return new Date(cert.notAfter) < new Date();
    });

    const expiresWithin30Days = $derived(() => {
        const expiry = new Date(cert.notAfter);
        const now = new Date();
        const thirtyDays = 30 * 24 * 60 * 60 * 1000;
        return expiry.getTime() - now.getTime() < thirtyDays && expiry > now;
    });
</script>

<div class="cert-card">
    <button class="cert-header" onclick={() => expanded = !expanded}>
        <span class="chevron" class:rotated={expanded}>▶</span>
        <h2>{label}</h2>
        {#if cert.isCA}
            <span class="badge ca">CA</span>
        {/if}
        {#if isExpired()}
            <span class="badge expired">Expired</span>
        {:else if expiresWithin30Days()}
            <span class="badge expiring">Expiring Soon</span>
        {/if}
    </button>

    {#if expanded}
        <div class="cert-body">
            <table>
              <tbody>
                <tr>
                    <td class="field-label">Subject</td>
                    <td class="field-value monospace">{cert.subject}</td>
                </tr>
                <tr>
                    <td class="field-label">Issuer</td>
                    <td class="field-value monospace">{cert.issuer}</td>
                </tr>
                <tr>
                    <td class="field-label">Serial Number</td>
                    <td class="field-value monospace">{cert.serialNumber}</td>
                </tr>
                <tr>
                    <td class="field-label">Version</td>
                    <td class="field-value">v{cert.version}</td>
                </tr>
                <tr>
                    <td class="field-label">Not Before</td>
                    <td class="field-value">{cert.notBefore}</td>
                </tr>
                <tr>
                    <td class="field-label">Not After</td>
                    <td class="field-value" class:expired-text={isExpired()} class:expiring-text={expiresWithin30Days()}>
                        {cert.notAfter}
                    </td>
                </tr>
                <tr>
                    <td class="field-label">Signature Algorithm</td>
                    <td class="field-value">{cert.signatureAlgorithm}</td>
                </tr>
                <tr>
                    <td class="field-label">Public Key</td>
                    <td class="field-value">{cert.publicKeyAlgorithm} ({cert.publicKeySize} bit)</td>
                </tr>

                {#if cert.dnsNames?.length}
                    <tr>
                        <td class="field-label">DNS Names</td>
                        <td class="field-value">
                            {#each cert.dnsNames as name}
                                <span class="tag">{name}</span>
                            {/each}
                        </td>
                    </tr>
                {/if}

                {#if cert.ipAddresses?.length}
                    <tr>
                        <td class="field-label">IP Addresses</td>
                        <td class="field-value">
                            {#each cert.ipAddresses as ip}
                                <span class="tag">{ip}</span>
                            {/each}
                        </td>
                    </tr>
                {/if}

                {#if cert.emailAddresses?.length}
                    <tr>
                        <td class="field-label">Email Addresses</td>
                        <td class="field-value">
                            {#each cert.emailAddresses as email}
                                <span class="tag">{email}</span>
                            {/each}
                        </td>
                    </tr>
                {/if}

                {#if cert.keyUsages?.length}
                    <tr>
                        <td class="field-label">Key Usage</td>
                        <td class="field-value">
                            {#each cert.keyUsages as usage}
                                <span class="tag">{usage}</span>
                            {/each}
                        </td>
                    </tr>
                {/if}

                {#if cert.extKeyUsages?.length}
                    <tr>
                        <td class="field-label">Extended Key Usage</td>
                        <td class="field-value">
                            {#each cert.extKeyUsages as usage}
                                <span class="tag">{usage}</span>
                            {/each}
                        </td>
                    </tr>
                {/if}
              </tbody>
            </table>
        </div>
    {/if}
</div>

<style>
    .cert-card {
        background: var(--vscode-editorWidget-background);
        border: 1px solid var(--vscode-widget-border);
        border-radius: 6px;
        margin-bottom: 12px;
        overflow: hidden;
    }

    .cert-header {
        display: flex;
        align-items: center;
        gap: 8px;
        width: 100%;
        padding: 12px 16px;
        background: transparent;
        border: none;
        color: var(--vscode-foreground);
        cursor: pointer;
        font-family: var(--vscode-font-family);
        font-size: inherit;
        text-align: left;
    }

    .cert-header:hover {
        background: var(--vscode-list-hoverBackground);
    }

    .chevron {
        font-size: 0.7em;
        transition: transform 0.15s ease;
        flex-shrink: 0;
    }

    .chevron.rotated {
        transform: rotate(90deg);
    }

    h2 {
        margin: 0;
        font-size: 1em;
        font-weight: 600;
    }

    .badge {
        font-size: 0.75em;
        padding: 2px 8px;
        border-radius: 10px;
        font-weight: 600;
        flex-shrink: 0;
    }

    .badge.ca {
        background: var(--vscode-statusBarItem-warningBackground);
        color: var(--vscode-statusBarItem-warningForeground);
    }

    .badge.expired {
        background: var(--vscode-statusBarItem-errorBackground);
        color: var(--vscode-statusBarItem-errorForeground);
    }

    .badge.expiring {
        background: var(--vscode-statusBarItem-warningBackground);
        color: var(--vscode-statusBarItem-warningForeground);
    }

    .cert-body {
        padding: 0 16px 16px;
    }

    table {
        border-collapse: collapse;
        width: 100%;
    }

    tr {
        border-bottom: 1px solid var(--vscode-widget-border);
    }

    tr:last-child {
        border-bottom: none;
    }

    td {
        padding: 6px 0;
        vertical-align: top;
    }

    .field-label {
        font-weight: 600;
        color: var(--vscode-descriptionForeground);
        white-space: nowrap;
        width: 180px;
        padding-right: 16px;
    }

    .field-value {
        word-break: break-all;
    }

    .monospace {
        font-family: var(--vscode-editor-font-family);
        font-size: 0.9em;
    }

    .expired-text {
        color: var(--vscode-errorForeground);
        font-weight: 600;
    }

    .expiring-text {
        color: var(--vscode-editorWarning-foreground);
        font-weight: 600;
    }

    .tag {
        display: inline-block;
        background: var(--vscode-badge-background);
        color: var(--vscode-badge-foreground);
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.85em;
        margin: 2px 4px 2px 0;
        font-family: var(--vscode-editor-font-family);
    }
</style>
