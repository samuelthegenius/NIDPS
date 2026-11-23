import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Development only: `npm run dev` serves the dashboard on :5173 and forwards /api to
// the backend on :5000. changeOrigin stays false so the backend's same-origin check
// sees matching Host and Origin headers. In production the backend serves dist/ itself.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:5000', changeOrigin: false },
    },
  },
});
