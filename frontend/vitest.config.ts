import { defineConfig } from "vitest/config";

// vitest 設定。 jsdom 環境で `WebSocket` / `window` などブラウザ API を
// 部分的に利用可能にしておく (但しテストでは fake な WebSocket を inject
// するので jsdom の実装には依存しない)。
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    globals: false,
    css: false,
  },
});
