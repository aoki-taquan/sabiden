// storage.ts の XSS 対策回帰テスト (Issue #109)。
//
// 検証項目:
//   1. saveToken は **localStorage に書かない** (XSS 露出窓を作らない)
//   2. saveToken は in-memory + sessionStorage には書く (UX 維持)
//   3. clearToken でメモリ / sessionStorage / 旧 localStorage 残骸を消す
//   4. 旧バージョンが localStorage に残したトークンは loadToken 初回呼び出しで
//      sessionStorage に migration されつつ localStorage から削除される
//   5. consumeTokenFromHash は localStorage を経由せず、 URL からも消す
//   6. signal URL は機微でないので localStorage 永続化を維持

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  __resetTokenStateForTesting,
  clearToken,
  consumeTokenFromHash,
  loadSignalUrl,
  loadToken,
  saveSignalUrl,
  saveToken,
} from "./storage";

const TOKEN_KEY = "sabiden.token";
const SIGNAL_URL_KEY = "sabiden.signal_url";

beforeEach(() => {
  __resetTokenStateForTesting();
  localStorage.clear();
  sessionStorage.clear();
  // hash を綺麗にしておく。
  if (typeof window !== "undefined") {
    history.replaceState(null, "", window.location.pathname);
  }
});

afterEach(() => {
  __resetTokenStateForTesting();
  localStorage.clear();
  sessionStorage.clear();
});

describe("saveToken (Issue #109: do not write to localStorage)", () => {
  it("does NOT persist token to localStorage", () => {
    saveToken("ext1.999.sig");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("persists token to sessionStorage so same-tab reload still works", () => {
    saveToken("ext1.999.sig");
    expect(sessionStorage.getItem(TOKEN_KEY)).toBe("ext1.999.sig");
  });

  it("makes token immediately retrievable via loadToken (in-memory)", () => {
    saveToken("ext1.999.sig");
    expect(loadToken()).toBe("ext1.999.sig");
  });

  it("scrubs any pre-existing localStorage token to remove the XSS window", () => {
    // 攻撃者がストレージに事前に置いた値 (or 旧バージョンが書いた残骸)。
    localStorage.setItem(TOKEN_KEY, "stale-value");
    saveToken("new-token");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});

describe("clearToken (Issue #109)", () => {
  it("removes token from in-memory, sessionStorage, and any localStorage residue", () => {
    saveToken("ext1.999.sig");
    // 別経路で localStorage に紛れ込んだ古いキーがあった想定。
    localStorage.setItem(TOKEN_KEY, "stale");
    clearToken();
    expect(loadToken()).toBeNull();
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});

describe("loadToken legacy migration (Issue #109)", () => {
  it("migrates a legacy localStorage token into sessionStorage and deletes the original", () => {
    // 旧バージョンの sabiden が localStorage に書き残したトークン。
    localStorage.setItem(TOKEN_KEY, "legacy-token");

    const got = loadToken();
    expect(got).toBe("legacy-token");
    // localStorage から確実に削除されている。
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    // sessionStorage に移っている (タブ内では引き続き使える)。
    expect(sessionStorage.getItem(TOKEN_KEY)).toBe("legacy-token");
  });

  it("returns null when no token is anywhere", () => {
    expect(loadToken()).toBeNull();
  });

  it("prefers sessionStorage over legacy localStorage when both exist", () => {
    sessionStorage.setItem(TOKEN_KEY, "session-token");
    localStorage.setItem(TOKEN_KEY, "legacy-token");
    // session を優先 (= 同一タブで save 済みのものを尊重)。
    expect(loadToken()).toBe("session-token");
    // session が選ばれた場合でも legacy は scrub されないが、 次回 saveToken で
    // 確実に removeItem されるので XSS 窓口は閉じる方向に向かう。
    // (今回は明示的に scrub までは要求しない: session ヒット = ユーザが既に
    //  入力済 = 攻撃シナリオが先行している場合は別の問題)。
  });
});

describe("consumeTokenFromHash (Issue #109)", () => {
  it("extracts token from URL hash, stores in-memory + sessionStorage, and clears the URL", () => {
    history.replaceState(null, "", "/?foo=bar#token=ext1.999.sig");
    expect(window.location.hash).toBe("#token=ext1.999.sig");

    const got = consumeTokenFromHash();
    expect(got).toBe("ext1.999.sig");
    // URL ハッシュから消えている (history / clipboard 漏れ防止)。
    expect(window.location.hash).toBe("");
    // localStorage には書かない。
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    // sessionStorage には書く。
    expect(sessionStorage.getItem(TOKEN_KEY)).toBe("ext1.999.sig");
    // loadToken でも引ける (in-memory)。
    expect(loadToken()).toBe("ext1.999.sig");
  });

  it("returns null when no #token= is present", () => {
    history.replaceState(null, "", "/?foo=bar");
    expect(consumeTokenFromHash()).toBeNull();
  });

  it("ignores other hash params that are not `token`", () => {
    history.replaceState(null, "", "/#other=value");
    expect(consumeTokenFromHash()).toBeNull();
    // hash は手付かず (token 由来でない hash は触らない)。
    expect(window.location.hash).toBe("#other=value");
  });
});

describe("signal URL persistence (non-sensitive: stays in localStorage)", () => {
  it("saves and loads signal URL via localStorage (stable across tabs)", () => {
    saveSignalUrl("wss://example.com/signal");
    expect(localStorage.getItem(SIGNAL_URL_KEY)).toBe("wss://example.com/signal");
    expect(loadSignalUrl()).toBe("wss://example.com/signal");
  });

  it("clears signal URL when an empty string is passed", () => {
    saveSignalUrl("wss://example.com/signal");
    saveSignalUrl("");
    expect(loadSignalUrl()).toBeNull();
  });
});

describe("XSS attack scenario (Issue #109 acceptance)", () => {
  // OWASP HTML5 Security: 同一オリジン上で動く悪意 script が localStorage を
  // 走査してもトークンが取れない、 を E2E 風に再現する。
  it("hostile script reading localStorage finds nothing token-shaped", () => {
    // 通常ログインフロー
    saveToken("ext1.999.signature");

    // 攻撃者の script が localStorage を全件スキャン:
    const exfiltrated: Record<string, string> = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) exfiltrated[key] = localStorage.getItem(key) ?? "";
    }
    // signal URL のような非機微エントリは出てよいが、 token は無いこと。
    const values = Object.values(exfiltrated);
    expect(values).not.toContain("ext1.999.signature");
    // キー名でも漏れていないこと。
    expect(exfiltrated[TOKEN_KEY]).toBeUndefined();
  });

  it("hostile script triggering same-tab reload still cannot widen the leak window", () => {
    // sessionStorage には居るが、 これはタブを閉じると消える。
    // 攻撃者が long-running script で永続化を狙っても localStorage 経由は
    // 閉じている (saveToken が removeItem するため)。
    saveToken("ext1.999.signature");
    // 攻撃者が偽 token を localStorage に植えても、
    // 次回 saveToken / clearToken で消える (defense-in-depth):
    localStorage.setItem(TOKEN_KEY, "planted-by-attacker");
    saveToken("ext1.999.signature");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});
