import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// The AEGIS service listens on 8080 (src/aegis/service/server.py, DEFAULT_PORT).
const AEGIS_ORIGIN = process.env.AEGIS_ORIGIN ?? 'http://127.0.0.1:8080'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // The dashboard calls `/api/health` and `/api/incident`; the service exposes those
      // at `/health` and `/incident`. Proxying under a prefix rather than at the root
      // keeps the SPA's own routes (`/overview`, `/incidents`, …) reachable — a bare `/`
      // proxy would send every page load to the Python service instead of to React.
      '/api': {
        target: AEGIS_ORIGIN,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
})
