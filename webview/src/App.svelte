<script lang="ts">
  import './app.css';
  import { fromBinary } from '@bufbuild/protobuf';
  import { ParseResponseSchema, type ParseResponse } from './lib/proto/discocrypto/v1/parser_pb';
  import { encodingName } from './lib/utils/format';
  import ObjectViewer from './lib/components/ObjectViewer.svelte';

  const vscode = (globalThis as any).acquireVsCodeApi();

  let response = $state<ParseResponse | null>(null);
  let error = $state<string | null>(null);
  let filename = $state('');
  let loading = $state(true);
  let needsPassphrase = $state(false);
  let passphrase = $state('');

  // Signal to the extension that the webview script is loaded and ready.
  vscode.postMessage({ type: 'ready' });

  window.addEventListener('message', (event) => {
    const msg = event.data;
    if (msg.type === 'parsed') {
      try {
        filename = msg.filename;
        const bytes = new Uint8Array(msg.data);
        response = fromBinary(ParseResponseSchema, bytes);
        error = null;
      } catch (e) {
        error = e instanceof Error ? e.message : 'Failed to parse response';
        response = null;
      }
      loading = false;
    } else if (msg.type === 'error') {
      if (msg.message.includes('password incorrect') || msg.message.includes('decryption password')) {
        needsPassphrase = true;
        error = null;
      } else {
        error = msg.message;
        needsPassphrase = false;
      }
      response = null;
      loading = false;
    }
  });
</script>

<main class="dc-app">
  {#if loading}
    <div class="dc-loading">
      <div class="dc-spinner"></div>
      <span>Parsing cryptographic data...</span>
    </div>
  {:else if needsPassphrase}
    <div class="dc-passphrase">
      <div class="dc-passphrase-title">This file requires a passphrase</div>
      <form onsubmit={(e) => { e.preventDefault(); loading = true; needsPassphrase = false; vscode.postMessage({ type: 'retry', passphrase }); passphrase = ''; }}>
        <input type="password" bind:value={passphrase} placeholder="Enter passphrase" class="dc-passphrase-input" />
        <button type="submit" class="dc-passphrase-btn">Unlock</button>
      </form>
    </div>
  {:else if error}
    <div class="dc-error">{error}</div>
  {:else if response}
    {#if filename}
      <div class="dc-filename">{filename}</div>
    {/if}

    {#if response.objects.length === 0}
      <div class="dc-empty">
        <div class="dc-empty-title">No cryptographic objects detected</div>
        <div>The file could not be parsed as a known cryptographic format.</div>
      </div>
    {:else}
      {#if response.detectedEncoding}
        <div style="margin-bottom: 12px; font-size: 0.82em; color: var(--dc-text-dim); text-transform: uppercase; letter-spacing: 0.04em">
          Encoding: {encodingName(response.detectedEncoding)}
          &middot; {response.objects.length} object{response.objects.length !== 1 ? 's' : ''}
        </div>
      {/if}

      {#each response.objects as obj, i}
        {#if i > 0}
          <div style="margin: 16px 0; border-top: 2px solid var(--dc-border)"></div>
        {/if}
        <ObjectViewer object={obj} />
      {/each}
    {/if}
  {/if}
</main>
