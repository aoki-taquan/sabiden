import { defineConfig } from "vitest/config";

// vitest 設定。 Cloudflare Workers Runtime に依存しない純粋な関数寄りの
// 単体テスト (signaling-proxy の proxySignal を fetch mock で叩く) を node
// 環境で実行する。 miniflare/wrangler は CI 環境で立てづらいので避ける。
export default defineConfig({
  test: {
    environment: "node",
    include: ["*.test.ts", "**/*.test.ts"],
    globals: false,
  },
});
