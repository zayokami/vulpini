import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  root: 'electron/renderer',
  publicDir: 'public',
  build: {
    outDir: '../../dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  resolve: {
    alias: {
      '@shared': path.resolve(__dirname, '../shared'),
    },
  },
});
