import tailwindcss from '@tailwindcss/vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';
import { resolve } from 'path';

export default defineConfig({
    plugins: [tailwindcss(), svelte()],
    build: {
        outDir: '../dist/webview',
        emptyOutDir: true,
        rollupOptions: {
            input: resolve(__dirname, 'index.html'),
            output: {
                entryFileNames: 'main.js',
                assetFileNames: '[name][extname]',
            },
        },
    },
});
