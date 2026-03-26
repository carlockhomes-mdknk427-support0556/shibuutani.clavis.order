import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/shibuutani.clavis.order/',
  build: { outDir: 'docs' },
})
