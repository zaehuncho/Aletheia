import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

export default defineConfig(async () => ({
    plugins: [react(), tailwindcss()],
    clearScreen: false,
    server: {
        port: 1420,
        strictPort: true,
        host: "0.0.0.0",
        hmr: { protocol: "ws", host: "0.0.0.0", port: 1421 },
        watch: { ignored: ["**/src-tauri/**"] },
    },
}))
