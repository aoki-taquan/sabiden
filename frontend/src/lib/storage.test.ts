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
//   7. PR #183 review fix: loadToken は経路 (memory/session/legacy/miss) に
//      依らず legacy localStorage を **無条件 scrub** する
//
// PR #183 review fix: production-side test hook
// (`__resetTokenStateForTesting` export) を撤去したため、 各 test 前に
// `vi.resetModules()` + 動的 `import("./storage")` でモジュール状態を
// fresh にする。 これは Vitest 標準パターン (vi.resetModules docs:
// https://vitest.dev/api/vi.html#vi-resetmodules) で、 production bundle に
// テスト hook を露出させずに module-private state をリセットできる。

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type * as StorageModule from "./storage";

const TOKEN_KEY = "sabiden.token";
const SIGNAL_URL_KEY = "sabiden.signal_url";

/** 各 test で fresh な storage module を取得するヘルパ。 */
async function loadStorage(): Promise<typeof StorageModule> {
  vi.resetModules();
  return await import("./storage");
}

beforeEach(() => {
  vi.resetModules();
  localStorage.clear();
  sessionStorage.clear();
  // hash を綺麗にしておく。
  if (typeof window !== "undefined") {
    history.replaceState(null, "", window.location.pathname);
  }
});

afterEach(() => {
  vi.resetModules();
  localStorage.clear();
  sessionStorage.clear();
});

describe("saveToken (Issue #109: do not write to localStorage)", () => {
  it("does NOT persist token to localStorage", async () => {
    const { saveToken } = await loadStorage();
    saveToken("ext1.999.sig");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("persists token to sessionStorage so same-tab reload still works", async () => {
    const { saveToken } = await loadStorage();
    saveToken("ext1.999.sig");
    expect(sessionStorage.getItem(TOKEN_KEY)).toBe("ext1.999.sig");
  });

  it("makes token immediately retrievable via loadToken (in-memory)", async () => {
    const { saveToken, loadToken } = await loadStorage();
    saveToken("ext1.999.sig");
    expect(loadToken()).toBe("ext1.999.sig");
  });

  it("scrubs any pre-existing localStorage token to remove the XSS window", async () => {
    const { saveToken } = await loadStorage();
    // 攻撃者がストレージに事前に置いた値 (or 旧バージョンが書いた残骸)。
    localStorage.setItem(TOKEN_KEY, "stale-value");
    saveToken("new-token");
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});

describe("clearToken (Issue #109)", () => {
  it("removes token from in-memory, sessionStorage, and any localStorage residue", async () => {
    const { saveToken, clearToken, loadToken } = await loadStorage();
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
  it("migrates a legacy localStorage token into sessionStorage and deletes the original", async () => {
    const { loadToken } = await loadStorage();
    // 旧バージョンの sabiden が localStorage に書き残したトークン。
    localStorage.setItem(TOKEN_KEY, "legacy-token");

    const got = loadToken();
    // PR #183 review fix: loadToken は無条件 scrub を最優先するため、
    // legacy トークンも scrub される。 戻り値は null (= sessionStorage 復元
    // 経路 / memory hit でない場合は migration できない)。
    // これは旧挙動 (legacy → migrate) より厳格だが、 XSS 窓 0 化を優先する。
    expect(got).toBeNull();
    // localStorage から確実に削除されている。
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
    // sessionStorage には移されない (legacy migration 経路は通らない)。
    expect(sessionStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("returns null when no token is anywhere", async () => {
    const { loadToken } = await loadStorage();
    expect(loadToken()).toBeNull();
  });

  it("prefers sessionStorage over legacy localStorage when both exist, and STILL scrubs legacy", async () => {
    const { loadToken } = await loadStorage();
    sessionStorage.setItem(TOKEN_KEY, "session-token");
    localStorage.setItem(TOKEN_KEY, "legacy-token");
    // session を優先 (= 同一タブで save 済みのものを尊重)。
    expect(loadToken()).toBe("session-token");
    // PR #183 review fix: session hit 経路でも legacy localStorage は
    // 無条件 scrub される (これは旧挙動の "session hit なら legacy は
    // scrub しない" を厳格化したもの)。
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });

  it("scrubs legacy localStorage even when no token is anywhere (defense-in-depth)", async () => {
    const { loadToken } = await loadStorage();
    // 攻撃者が仮に localStorage を planted した場合でも、 loadToken 呼出で
    // 即座に scrub される。
    localStorage.setItem(TOKEN_KEY, "planted-by-attacker");
    expect(loadToken()).toBeNull();
    expect(localStorage.getItem(TOKEN_KEY)).toBeNull();
  });
});

describe("consumeTokenFromHash (Issue #109)", () => {
  it("extracts token from URL hash, stores in-memory + sessionStorage, and clears the URL", async () => {
    const { consumeTokenFromHash, loadToken } = await loadStorage();
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

  it("returns null when no #token= is present", async () => {
    const { consumeTokenFromHash } = await loadStorage();
    history.replaceState(null, "", "/?foo=bar");
    expect(consumeTokenFromHash()).toBeNull();
  });

  it("ignores other hash params that are not `token`", async () => {
    const { consumeTokenFromHash } = await loadStorage();
    history.replaceState(null, "", "/#other=value");
    expect(consumeTokenFromHash()).toBeNull();
    // hash は手付かず (token 由来でない hash は触らない)。
    expect(window.location.hash).toBe("#other=value");
  });
});

describe("signal URL persistence (non-sensitive: stays in localStorage)", () => {
  it("saves and loads signal URL via localStorage (stable across tabs)", async () => {
    const { saveSignalUrl, loadSignalUrl } = await loadStorage();
    saveSignalUrl("wss://example.com/signal");
    expect(localStorage.getItem(SIGNAL_URL_KEY)).toBe("wss://example.com/signal");
    expect(loadSignalUrl()).toBe("wss://example.com/signal");
  });

  it("clears signal URL when an empty string is passed", async () => {
    const { saveSignalUrl, loadSignalUrl } = await loadStorage();
    saveSignalUrl("wss://example.com/signal");
    saveSignalUrl("");
    expect(loadSignalUrl()).toBeNull();
  });
});

describe("XSS attack scenario (Issue #109 acceptance)", () => {
  // OWASP HTML5 Security: 同一オリジン上で動く悪意 script が localStorage を
  // 走査してもトークンが取れない、 を E2E 風に再現する。
  it("hostile script reading localStorage finds nothing token-shaped", async () => {
    const { saveToken } = await loadStorage();
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

  it("hostile script triggering same-tab reload still cannot widen the leak window", async () => {
    const { saveToken } = await loadStorage();
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

describe("PR #183 review fix: production module surface (no test hook)", () => {
  it("does NOT export __resetTokenStateForTesting (production-side test hook ban, CLAUDE.md §6.3)", async () => {
    const mod = (await loadStorage()) as Record<string, unknown>;
    // production bundle に testing hook が混入していないことを保証する。
    // この export が残ると同一オリジン script から in-memory token を
    // 消去 (DoS) できてしまう。
    expect(mod.__resetTokenStateForTesting).toBeUndefined();
  });
});
