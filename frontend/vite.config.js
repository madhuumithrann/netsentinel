import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The dev server and preview server only listen on this machine. API calls go to a
// relative /api path and are proxied to the FastAPI backend, so no CORS setup is needed
// and the backend URL is never hard-coded in the UI.
const backend = process.env.NETSENTINEL_API || 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: { '/api': { target: backend, changeOrigin: false } },
  },
  preview: {
    host: '127.0.0.1',
    port: 4173,
    proxy: { '/api': { target: backend, changeOrigin: false } },
  },
});
