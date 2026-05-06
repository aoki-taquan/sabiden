# PWA アイコン

このディレクトリには PWA マニフェストから参照される PNG アイコンを置く:

- `icon-192.png` (192x192)
- `icon-512.png` (512x512, maskable 推奨)

`icon.svg` から生成できる:

```bash
# rsvg-convert / inkscape / sharp などで:
npx sharp-cli -i icon.svg -o icon-192.png resize 192 192
npx sharp-cli -i icon.svg -o icon-512.png resize 512 512
```

CI では `vite-plugin-pwa` が manifest を生成するため、これらの PNG が
`public/icons/` に存在すれば自動でハッシュバンドルされる。
本リポジトリはバイナリを置かず、デプロイ前に各自生成する方針。
