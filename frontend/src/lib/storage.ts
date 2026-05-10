// 認証トークン保管 (Issue #109 hardening: localStorage → in-memory + sessionStorage)。
//
// HMAC アクセストークンは sabiden の `/signal` WS bearer に等しい権限を持つ
// (有効期限内なら任意の通話を内線として発信・着信できる)。 同一オリジンに
// 入った任意 script (XSS / 将来の依存 supply chain attack) から
// `localStorage.getItem("sabiden.token")` で読み出されると即流出するため、
// 永続化を撤去する:
//
//   - **primary**: モジュールローカル変数 (in-memory)。 ページ遷移 / リロードで消える。
//   - **fallback**: `sessionStorage` (タブ単位、 タブを閉じれば自動消去)。
//     iOS Safari の Service Worker 経由 background reload や PWA 復帰時に
//     UX を保つための妥協 (永続化先としての localStorage と違い、 別タブ /
//     別 origin / タブクローズ後の script からは到達できない)。
//
// 根拠:
//   - OWASP ASVS V3.2 / OWASP HTML5 Security Cheat Sheet:
//     "Sensitive session tokens MUST NOT be stored in localStorage"
//   - sabiden Issue #109 提案 §修正案 1〜3
//   - `docs/CLOUDFLARE.md` Phase 2 で本来は HttpOnly Cookie + Cf-Access-Jwt の
//     経路に置換予定。 本変更はその過渡期での緩和措置。
//
// signal URL は機微でない (公開する WSS エンドポイントの単なる UX 設定) ので
// 従来通り `localStorage` に置く。

const TOKEN_SESSION_KEY = "sabiden.token";
const SIGNAL_URL_KEY = "sabiden.signal_url";
/** Issue #109 旧運用との互換: 起動時に一度だけ localStorage から拾って消す。 */
const LEGACY_TOKEN_LOCAL_KEY = "sabiden.token";

/**
 * In-memory token cache。 SignalingClient へ渡したあとはこの値が source of
 * truth で、 sessionStorage は「タブ内リロードで失わない」 ためのバックアップ。
 */
let memoryToken: string | null = null;

/** sessionStorage に touch しようとして失敗 (private mode 等) しても無視するヘルパ。 */
function trySession<T>(fn: () => T, fallback: T): T {
  try {
    return fn();
  } catch {
    return fallback;
  }
}

/**
 * 起動時 (`App.tsx::onMount`) に呼ばれ、 旧バージョンが localStorage に残した
 * トークンを **撤去** する。 同時にメモリへ移送して既存ユーザの「リロードで
 * 突然ログアウト」 体験を一度だけ救済する (UX guard)。 この一回限りの移送後は
 * localStorage から確実に消えるので、 XSS 露出窓は次回以降残らない。
 */
function migrateLegacyLocalToken(): string | null {
  try {
    const legacy = localStorage.getItem(LEGACY_TOKEN_LOCAL_KEY);
    if (!legacy) return null;
    localStorage.removeItem(LEGACY_TOKEN_LOCAL_KEY);
    return legacy;
  } catch {
    return null;
  }
}

/**
 * 現在保持しているトークンを返す (in-memory 優先)。
 * 同一タブの 2 度目以降の onMount / リロード時は sessionStorage から復元する。
 * 旧 localStorage に残っていた token は本関数の初回呼び出し時にメモリへ移送
 * しつつ localStorage から削除する (Issue #109 一回限りの migration)。
 */
export function loadToken(): string | null {
  if (memoryToken) return memoryToken;
  const fromSession = trySession(() => sessionStorage.getItem(TOKEN_SESSION_KEY), null);
  if (fromSession) {
    memoryToken = fromSession;
    return memoryToken;
  }
  const legacy = migrateLegacyLocalToken();
  if (legacy) {
    memoryToken = legacy;
    trySession(() => sessionStorage.setItem(TOKEN_SESSION_KEY, legacy), undefined);
    return memoryToken;
  }
  return null;
}

/**
 * トークンを保存する。 in-memory は常に書く、 sessionStorage は best-effort。
 * Issue #109: localStorage には **書かない**。
 */
export function saveToken(token: string): void {
  memoryToken = token;
  trySession(() => sessionStorage.setItem(TOKEN_SESSION_KEY, token), undefined);
  // 過去の localStorage 痕跡があれば確実に消す (defense-in-depth、 本関数経由の
  // 新規書込ルートでも残骸を 0 にしておく)。
  try {
    localStorage.removeItem(LEGACY_TOKEN_LOCAL_KEY);
  } catch {
    /* ignore */
  }
}

export function clearToken(): void {
  memoryToken = null;
  trySession(() => sessionStorage.removeItem(TOKEN_SESSION_KEY), undefined);
  try {
    localStorage.removeItem(LEGACY_TOKEN_LOCAL_KEY);
  } catch {
    /* ignore */
  }
}

/** ユーザが指定したシグナリング URL は機微情報ではないので localStorage で永続化。 */
export function loadSignalUrl(): string | null {
  try {
    return localStorage.getItem(SIGNAL_URL_KEY);
  } catch {
    return null;
  }
}

export function saveSignalUrl(url: string): void {
  try {
    if (url) localStorage.setItem(SIGNAL_URL_KEY, url);
    else localStorage.removeItem(SIGNAL_URL_KEY);
  } catch {
    /* ignore */
  }
}

/**
 * URL ハッシュフラグメント `#token=xxx` から取り出して保管し、 URL から消す。
 * ハッシュ部はサーバへ送信されない (RFC 3986 §3.5) のでクエリより安全。
 * 取り込んだ後は `history.replaceState` で URL バーから消し、 履歴 / コピペ
 * からの漏洩を防ぐ (Issue #109 修正案 §3)。
 */
export function consumeTokenFromHash(): string | null {
  if (typeof window === "undefined" || !window.location.hash) return null;
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const t = params.get("token");
  if (!t) return null;
  saveToken(t);
  history.replaceState(null, "", window.location.pathname + window.location.search);
  return t;
}

/** テスト専用: in-memory state を初期化する。 production code から呼ばない。 */
export function __resetTokenStateForTesting(): void {
  memoryToken = null;
}
