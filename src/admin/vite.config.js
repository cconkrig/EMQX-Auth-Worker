import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: __dirname,
  build: {
    outDir: path.resolve(__dirname, '../../static'),
    emptyOutDir: true
  },
  plugins: [svelte()]
}); 