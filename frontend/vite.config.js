import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Without this, a second `npm run dev` silently slides to 5174 (then 5175,
    // ...) instead of reporting the conflict. That produced a confusing second
    // dev server whose origin was missing from CORS, so its API calls failed and
    // the app looked broken. Fail loudly and keep a single dev server.
    strictPort: true,
  },
})
