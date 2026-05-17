// sabiden PWA Service Worker (Issue #294)
//
// sabiden が NGN inbound INVITE 受領時に Web Push (RFC 8030 / 8291 VAPID) を
// 送ってくる。 本 SW は `push` event で payload を取り出し、 Notification API
// で着信通知を表示する (W3C Push API §6 / §7)。
//
// payload 形式 (`src/webrtc/push.rs::IncomingCallPayload`):
//   { "type": "incoming_call", "call_id": "...", "caller_number": "...", "issued_at": <unix s> }
//
// 通知 tap → `notificationclick` event → `clients.openWindow` で PWA を開く
// (= /#call_id=<id> 形式で route 復元する想定。 PWA 側は token を sessionStorage
// から復元して `register` 経路に乗る)。
//
// vite-plugin-pwa は `injectManifest` strategy で本ファイルを base に
// `self.__WB_MANIFEST` (precache manifest) を inject する。 workbox の precache
// は使わず本 SW では参照のみ (= lint 警告抑制) し、 アプリ assets は通常の
// fetch で配信する (PWA navigateFallback は不要、 PWA はあくまで「通知を出す」
// 目的)。

// vite-plugin-pwa injectManifest 仕様: build 時に `self.__WB_MANIFEST` を
// 参照する箇所が必須 (workbox-build が文字列パターン置換する)。 実 precache
// は不要だが (sabiden は frontend を axum / Cloudflare Worker 直配信、 SW
// での precache 利得は薄い)、 build 通すために空配列に fallback で参照する。
// 副作用なしの noop だが minifier の dead-code elimination 対策で
// `self._sabidenManifest` (= 大域 property) に書き出して保持する。
self._sabidenManifest = self.__WB_MANIFEST || [];

self.addEventListener("install", (event) => {
  // 即時 activate (旧バージョン SW を即座に置換し、 古い event handler が
  // 残らないようにする)。 ServiceWorker §3.2.1 Skip Waiting algorithm。
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  // 全 client (= 既存 PWA tab) を即座に新 SW の制御下に置く
  // (Issue #294: 通知を最初の利用から有効化するため)。
  event.waitUntil(self.clients.claim());
});

/**
 * RFC 8030 §5 / W3C Push API §6: push event 受信時、 payload を取り出して
 * 通知を表示する。 payload が空 / parse 失敗でも generic な「着信通知」 を
 * 表示する (silent push は iOS Safari でブラウザに拒否されるため必須)。
 */
self.addEventListener("push", (event) => {
  let payload = null;
  try {
    payload = event.data?.json() ?? null;
  } catch (e) {
    // ASCII text 等 JSON 以外の payload にもフォールバック。
    payload = null;
  }

  const isIncomingCall = payload?.type === "incoming_call";
  const callerNumber = isIncomingCall
    ? String(payload.caller_number ?? "非通知")
    : "着信";
  const callId = isIncomingCall ? String(payload.call_id ?? "") : "";

  // RFC 8030 で payload は encrypted body だが、 表示時には plain JSON。
  // Notification body にユーザ表示する。 RTL / 絵文字を抑止して短文にする。
  const title = "sabiden 着信";
  const body = `${callerNumber} から着信中`;
  const options = {
    body,
    tag: callId || "sabiden-incoming-call",
    // 既存通知 (同 tag) は上書き (= 同一通話の重複通知を避ける)。
    renotify: false,
    requireInteraction: true,
    data: { callId, callerNumber, kind: payload?.type ?? "unknown" },
    // iOS Safari は icon を強制要求するため public/icons/icon-192.png を指す。
    icon: "/icons/icon-192.png",
    badge: "/icons/icon-192.png",
    // RFC 7240 prefer は HTTP 用、 ここでは N/A。 actions は Chrome/Android のみ。
    actions: [
      { action: "accept", title: "応答" },
      { action: "decline", title: "拒否" },
    ],
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

/**
 * 通知タップ → PWA を開く (= 既存タブにフォーカス、 無ければ新規 window)。
 * URL に `#call_id=<id>` を付けて PWA が answer / decline を続行できるようにする。
 *
 * action ボタン (Chrome/Android) は `event.action` で識別する:
 *   - "accept": 応答
 *   - "decline": 拒否 (PWA で `decline` ClientMessage を送る)
 *   - "" (本文タップ): デフォルト = PWA を前面化
 */
self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const callId = data.callId || "";
  const action = event.action || "";
  // PWA URL を hash で route 復元 (token は PWA 側 sessionStorage から)。
  const url = callId
    ? `/?#incoming=${encodeURIComponent(callId)}&action=${encodeURIComponent(action)}`
    : "/";

  event.waitUntil(
    (async () => {
      const allClients = await self.clients.matchAll({
        type: "window",
        includeUncontrolled: true,
      });
      for (const client of allClients) {
        // 同一 origin の既存 window があれば post message + focus。
        if ("focus" in client) {
          try {
            client.postMessage({
              type: "incoming_call_action",
              callId,
              action,
            });
          } catch (e) {
            // ignore
          }
          return client.focus();
        }
      }
      // 既存 window が無ければ新規で開く。
      if (self.clients.openWindow) {
        return self.clients.openWindow(url);
      }
      return null;
    })(),
  );
});

// 通知を閉じた (= reject / X 押下) 時のフック。 統計 / カウントを取りたい
// 場合はここで window 側 client に postMessage する。 現状は no-op。
self.addEventListener("notificationclose", (_event) => {
  // no-op
});
