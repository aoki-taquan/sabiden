import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import { VitePWA } from "vite-plugin-pwa";

// PWA フロントエンドのビルド設定。
// dev サーバから sabiden の WebSocket 経路 (`/signal`) をプロキシし、
// 本番では Cloudflare Workers (workers/) が `/signal` をパススルー。
export default defineConfig({
  plugins: [
    solid(),
    VitePWA({
      registerType: "autoUpdate",
      includeAssets: ["icons/icon-192.png", "icons/icon-512.png"],
      manifest: {
        name: "sabiden",
        short_name: "sabiden",
        description: "NTT Hikari Phone WebRTC Client",
        theme_color: "#0a84ff",
        background_color: "#000000",
        display: "standalone",
        orientation: "portrait",
        start_url: "/",
        icons: [
          {
            src: "/icons/icon-192.png",
            sizes: "192x192",
            type: "image/png",
            purpose: "any maskable",
          },
          {
            src: "/icons/icon-512.png",
            sizes: "512x512",
            type: "image/png",
            purpose: "any maskable",
          },
        ],
      },
      workbox: {
        // /signal はリアルタイム WS なのでキャッシュしない
        navigateFallbackDenylist: [/^\/signal/],
        globPatterns: ["**/*.{js,css,html,svg,png,ico,webmanifest}"],
      },
    }),
  ],
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      // `VITE_SIGNAL_BACKEND` が設定されていれば dev でもバックエンド WS にプロキシ
      "/signal": {
        target: process.env.VITE_SIGNAL_BACKEND ?? "http://127.0.0.1:8080",
        changeOrigin: true,
        ws: true,
      },
    },
  },
  build: {
    target: "es2020",
    sourcemap: true,
    outDir: "dist",
  },
});
