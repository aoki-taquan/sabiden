// Web Push (Issue #294) クライアントヘルパ。
//
// Service Worker 登録 + `PushManager.subscribe` + sabiden への WS 経由
// 購読送信を担当する。 sabiden 側は RFC 8030 / RFC 8291 / RFC 8292 VAPID
// に従って push を送ってくる (`src/webrtc/push.rs`)。
//
// # ライフサイクル
//
// 1. `ensureServiceWorker()` で `/sw.js` を登録する (idempotent)。
// 2. `Notification.requestPermission()` でユーザ許可を取得する。
// 3. `GET /api/push/vapid-public-key` で VAPID 公開鍵を取得する
//    (RFC 8292 §3.2 uncompressed P-256 base64url)。
// 4. `PushManager.subscribe({ userVisibleOnly: true, applicationServerKey })`
//    で push subscription を取得する (W3C Push API §5.3)。
// 5. WS で `{ type: "pushsubscribe", endpoint, keys: { p256dh, auth } }` を
//    送る。 sabiden は `ServerMessage::PushSubscribed` で確認応答する。
//
// # iOS Safari 注意
//
// iOS 16.4+ で Web Push が有効化された。 ただし PWA を「ホーム画面に追加」
// 状態でしか動かない (Apple WWDC23)。 `BeforeInstallPromptEvent` は iOS では
// 発火しないため、 PWA メニューから手動 install してもらう前提。

import type { SignalingClient } from "./signaling";

/**
 * Service Worker を登録する (idempotent)。 既に登録済なら新規登録せず既存 registration を返す。
 * Service Worker が無効化されているブラウザ (= `serviceWorker` が undefined)
 * では reject する。
 */
export async function ensureServiceWorker(): Promise<ServiceWorkerRegistration> {
  if (!("serviceWorker" in navigator)) {
    throw new Error("このブラウザは Service Worker をサポートしていません");
  }
  // 既存登録があれば再利用 (scope 配下に複数 SW を作らないため)。
  const existing = await navigator.serviceWorker.getRegistration("/");
  if (existing) return existing;
  // 新規登録。 `/sw.js` は vite の `public/` 配下に置く (build で root に出る)。
  return navigator.serviceWorker.register("/sw.js", { scope: "/" });
}

/**
 * Notification API のユーザ許可を取得する。 `default` 状態のときだけ prompt を
 * 出す (`denied` で再 prompt しても許可されないので no-op)。
 */
export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (!("Notification" in window)) {
    throw new Error("このブラウザは Notification API をサポートしていません");
  }
  if (Notification.permission === "granted" || Notification.permission === "denied") {
    return Notification.permission;
  }
  return Notification.requestPermission();
}

/**
 * `/api/push/vapid-public-key` から VAPID 公開鍵を取得する。
 * RFC 8292 §3.2: uncompressed P-256 (65 byte) を base64url で encode したもの。
 * `applicationServerKey` に渡すためには `Uint8Array` (= 65 byte) に decode する。
 */
export async function fetchVapidPublicKey(apiBase: string = ""): Promise<Uint8Array> {
  const res = await fetch(`${apiBase}/api/push/vapid-public-key`, {
    method: "GET",
    credentials: "same-origin",
  });
  if (!res.ok) {
    throw new Error(`VAPID 公開鍵取得失敗: HTTP ${res.status}`);
  }
  const body = (await res.json()) as { publicKey: string };
  if (!body.publicKey) throw new Error("VAPID 公開鍵レスポンスに publicKey が無い");
  return base64UrlDecode(body.publicKey);
}

/** base64url (no padding) → Uint8Array. RFC 7515 §2 (Appendix C)。 */
export function base64UrlDecode(b64url: string): Uint8Array {
  // base64url → base64 (`-` → `+`, `_` → `/`, padding 補完)。
  const padLen = (4 - (b64url.length % 4)) % 4;
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(padLen);
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** Uint8Array → base64url (no padding)。 RFC 8291 §4.1 で auth/p256dh の wire format。 */
export function base64UrlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * 既存の push subscription を取り出す、 無ければ subscribe する。
 *
 * iOS Safari 16.4 でも動くように `userVisibleOnly: true` を必須化 (Safari は
 * silent push を禁止)。 同じ applicationServerKey で再 subscribe するのは
 * idempotent (PushManager 仕様 §5.3)。
 */
export async function subscribePush(
  registration: ServiceWorkerRegistration,
  applicationServerKey: Uint8Array,
): Promise<PushSubscription> {
  const existing = await registration.pushManager.getSubscription();
  if (existing) {
    // 鍵が変わった可能性があるので endpoint と applicationServerKey の整合
    // までは確認しない (= サーバ側で endpoint dedup される設計)。
    return existing;
  }
  // BufferSource は ArrayBuffer | TypedArray。 Uint8Array をそのまま渡せる。
  // Safari は ArrayBufferView を要求するブラウザがあるため bytes ではなく
  // bytes.buffer 経由でも互換性が取れるが、 仕様上はどちらでも OK。
  return registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: applicationServerKey as BufferSource,
  });
}

/**
 * PushSubscription を sabiden に WS で登録する。 sabiden は AOR (= 認証済
 * ext_id) に紐づけて store に保存する (RFC 8030 §3 + 8291 §4.1)。
 *
 * `PushSubscription.toJSON()` は `{ endpoint, keys: { p256dh, auth } }` の
 * 形式で base64url を含むため、 そのままサーバへ流す。
 */
export function sendSubscribeToSabiden(
  client: SignalingClient,
  subscription: PushSubscription,
): void {
  const json = subscription.toJSON() as {
    endpoint: string;
    keys: { p256dh: string; auth: string };
  };
  if (!json.endpoint || !json.keys?.p256dh || !json.keys?.auth) {
    throw new Error("PushSubscription に endpoint / keys が揃っていない");
  }
  client.send({
    type: "pushsubscribe",
    endpoint: json.endpoint,
    keys: { p256dh: json.keys.p256dh, auth: json.keys.auth },
  });
}

/**
 * 一連の flow を 1 関数で実行する高水準ヘルパ:
 *
 *   1. SW 登録
 *   2. 通知許可取得
 *   3. VAPID 公開鍵取得
 *   4. PushManager.subscribe
 *   5. sabiden に PushSubscribe 送信
 *
 * 失敗時は Error を throw する。 UI 側で catch して「通知有効化失敗」 trace を出す。
 *
 * @returns 登録した subscription の endpoint (UI 表示・dedup 判定に使う)
 */
export async function enablePushNotifications(
  client: SignalingClient,
  apiBase: string = "",
): Promise<string> {
  const reg = await ensureServiceWorker();
  const perm = await requestNotificationPermission();
  if (perm !== "granted") {
    throw new Error(`通知許可が下りていません (permission=${perm})`);
  }
  const vapid = await fetchVapidPublicKey(apiBase);
  const sub = await subscribePush(reg, vapid);
  sendSubscribeToSabiden(client, sub);
  return sub.endpoint;
}
