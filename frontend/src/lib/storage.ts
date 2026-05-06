// 認証トークン永続化。LocalStorage を使うが、本番では
// HttpOnly Cookie + Cloudflare Access の方が望ましい。
// (現状は HMAC のみのためクライアント保管が必要)

const TOKEN_KEY = "sabiden.token";
const SIGNAL_URL_KEY = "sabiden.signal_url";

export function loadToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function saveToken(token: string): void {
  try {
    localStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* private mode 等でストレージ無効 */
  }
}

export function clearToken(): void {
  try {
    localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
}

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

/** URL ハッシュフラグメント `#token=xxx` から取り出して保存し、URL から消す。 */
export function consumeTokenFromHash(): string | null {
  if (!window.location.hash) return null;
  const params = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const t = params.get("token");
  if (!t) return null;
  saveToken(t);
  // URL からトークンを取り除く (履歴に残さない)
  history.replaceState(null, "", window.location.pathname + window.location.search);
  return t;
}
