import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: __dirname,
  base: '/admin/', // Ensure all assets are referenced from /admin/
  build: {
    outDir: path.resolve(__dirname, '../../static/admin'),
    emptyOutDir: true
  },
  plugins: [svelte()]
}); 