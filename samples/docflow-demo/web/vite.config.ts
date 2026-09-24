import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { VitePWA } from "vite-plugin-pwa";

// Сборка кладётся в ../api/wwwroot — PWA раздаёт тот же процесс, что и API (один origin, без CORS).
// В dev-режиме Vite проксирует /api и /config.js на API (http://localhost:5200).
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    VitePWA({
      registerType: "autoUpdate",
      injectRegister: "auto",
      includeAssets: ["icon.svg"],
      manifest: {
        name: "Документооборот · TSL Auth",
        short_name: "Документы",
        description: "Демо-документооборот с входом через TSL Auth",
        lang: "ru",
        theme_color: "#4f46e5",
        background_color: "#0b1020",
        display: "standalone",
        start_url: "/",
        icons: [
          { src: "icon.svg", sizes: "any", type: "image/svg+xml", purpose: "any" },
          { src: "icon-maskable.svg", sizes: "any", type: "image/svg+xml", purpose: "maskable" }
        ]
      },
      workbox: {
        // API и вход не кэшируются: данные всегда свежие, а токены не должны попадать в кэш.
        navigateFallbackDenylist: [/^\/api\//, /^\/config\.js/, /^\/callback/],
        runtimeCaching: [
          { urlPattern: ({ url }) => url.pathname === "/config.js", handler: "NetworkFirst" }
        ]
      }
    })
  ],
  build: { outDir: "../api/wwwroot", emptyOutDir: true, chunkSizeWarningLimit: 1200 },
  server: {
    port: 5173,
    proxy: { "/api": "http://localhost:5200", "/config.js": "http://localhost:5200" }
  }
});
