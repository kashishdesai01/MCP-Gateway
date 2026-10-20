import { defineConfig, type ProxyOptions } from 'vite';
import react from '@vitejs/plugin-react';

// Vite-only development proxy. Normalize only the two explicit local UI
// origins; the service's production origin boundary remains unchanged.
const localProxy = (): ProxyOptions => ({
  target: 'http://localhost:3000',
  configure(proxy) {
    proxy.on('proxyReq', (request) => {
      const origin = request.getHeader('origin');
      if (origin === 'http://localhost:5173' || origin === 'http://127.0.0.1:5173') {
        request.setHeader('origin', 'http://localhost:3000');
      }
    });
  },
});
export default defineConfig({
  root: 'console',
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/admin': localProxy(),
      '/auth': localProxy(),
      '/demo': localProxy(),
      '/mcp': localProxy(),
    },
  },
  build: { outDir: 'dist', emptyOutDir: true },
});
