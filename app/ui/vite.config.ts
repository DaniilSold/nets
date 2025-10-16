import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const isTauri = process.env.TAURI_PLATFORM !== undefined;

export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    target: isTauri ? ['es2021', 'chrome100', 'safari13'] : 'es2020',
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 1420,
    strictPort: true,
    host: '0.0.0.0',
    fs: {
      allow: ['..']
    },
  },
  preview: {
    port: 1420,
    strictPort: true
  },
  resolve: {
    alias: {
      '@': '/src',
    },
  },
});
