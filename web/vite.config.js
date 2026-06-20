import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

// viteSingleFile inlines JS+CSS into ONE index.html so it opens with a plain
// double-click (file://) - no web server, no module/CORS issues.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  base: './',
})
