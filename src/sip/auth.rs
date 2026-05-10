/// RFC 2617 HTTP Digest 認証の計算
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub algorithm: String, // MD5 or MD5-sess
    pub qop: Option<String>,
    pub opaque: Option<String>,
}

impl DigestChallenge {
    pub fn parse(www_authenticate: &str) -> Result<Self> {
        let s = www_authenticate
            .trim_start_matches("Digest ")
            .trim_start_matches("digest ");

        let mut realm = String::new();
        let mut nonce = String::new();
        let mut algorithm = "MD5".to_string();
        let mut qop = None;
        let mut opaque = None;

        for part in split_auth_params(s) {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("bad auth param: {}", part))?;
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            match k {
                "realm" => realm = v.to_string(),
                "nonce" => nonce = v.to_string(),
                "algorithm" => algorithm = v.to_string(),
                "qop" => qop = Some(v.to_string()),
                "opaque" => opaque = Some(v.to_string()),
                _ => {}
            }
        }

        Ok(DigestChallenge {
            realm,
            nonce,
            algorithm,
            qop,
            opaque,
        })
    }
}

fn split_auth_params(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_quote = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => in_quote = !in_quote,
            ',' if !in_quote => {
                parts.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(s[start..].trim());
    parts
}

pub struct DigestCredentials {
    pub username: String,
    pub password: String,
}

pub struct DigestResponse {
    pub header_value: String,
    pub cnonce: String,
    pub nc: u32,
}

impl DigestCredentials {
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn compute(
        &self,
        challenge: &DigestChallenge,
        method: &str,
        uri: &str,
        nc: u32,
    ) -> DigestResponse {
        let cnonce = format!("{:016x}", rand::random::<u64>());

        let ha1 = md5_hex(&format!(
            "{}:{}:{}",
            self.username, challenge.realm, self.password
        ));
        let ha2 = md5_hex(&format!("{}:{}", method, uri));

        let response = if challenge.qop.as_deref() == Some("auth") {
            let nc_str = format!("{:08x}", nc);
            md5_hex(&format!(
                "{}:{}:{}:{}:auth:{}",
                ha1, challenge.nonce, nc_str, cnonce, ha2
            ))
        } else {
            md5_hex(&format!("{}:{}:{}", ha1, challenge.nonce, ha2))
        };

        let mut header = format!(
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}""#,
            self.username, challenge.realm, challenge.nonce, uri, response
        );

        if challenge.qop.as_deref() == Some("auth") {
            header.push_str(&format!(
                r#", qop=auth, nc={:08x}, cnonce="{}""#,
                nc, cnonce
            ));
        }

        if let Some(ref opaque) = challenge.opaque {
            header.push_str(&format!(r#", opaque="{}""#, opaque));
        }

        header.push_str(&format!(r#", algorithm={}"#, challenge.algorithm));

        DigestResponse {
            header_value: header,
            cnonce,
            nc,
        }
    }
}

fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

/// クライアントが送ってきた `Authorization:` ヘッダ値の構造体表現。
/// RFC 2617 / RFC 3261 §22 に従い、必要な属性のみ抽出する。
#[derive(Debug, Clone)]
pub struct DigestAuthorization {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: String,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
    pub opaque: Option<String>,
}

impl DigestAuthorization {
    /// `Authorization: Digest ...` の値部分をパースする。
    pub fn parse(authorization: &str) -> Result<Self> {
        let s = authorization
            .trim()
            .trim_start_matches("Digest ")
            .trim_start_matches("digest ");

        let mut username = String::new();
        let mut realm = String::new();
        let mut nonce = String::new();
        let mut uri = String::new();
        let mut response = String::new();
        let mut algorithm = "MD5".to_string();
        let mut qop = None;
        let mut nc = None;
        let mut cnonce = None;
        let mut opaque = None;

        for part in split_auth_params(s) {
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            let k = k.trim();
            let v = v.trim().trim_matches('"');
            match k {
                "username" => username = v.to_string(),
                "realm" => realm = v.to_string(),
                "nonce" => nonce = v.to_string(),
                "uri" => uri = v.to_string(),
                "response" => response = v.to_string(),
                "algorithm" => algorithm = v.to_string(),
                "qop" => qop = Some(v.to_string()),
                "nc" => nc = Some(v.to_string()),
                "cnonce" => cnonce = Some(v.to_string()),
                "opaque" => opaque = Some(v.to_string()),
                _ => {}
            }
        }

        if username.is_empty() || realm.is_empty() || nonce.is_empty() || response.is_empty() {
            anyhow::bail!("Authorization header missing required field");
        }
        Ok(DigestAuthorization {
            username,
            realm,
            nonce,
            uri,
            response,
            algorithm,
            qop,
            nc,
            cnonce,
            opaque,
        })
    }

    /// 与えられたパスワードで応答が正しいか検証する。
    /// RFC 2617 §3.2.2.1 の HA1/HA2 を再計算して定数時間比較する。
    pub fn verify(&self, method: &str, password: &str) -> bool {
        let ha1 = md5_hex(&format!("{}:{}:{}", self.username, self.realm, password));
        let ha2 = md5_hex(&format!("{}:{}", method, self.uri));
        let expected = if self.qop.as_deref() == Some("auth") {
            let nc = self.nc.as_deref().unwrap_or("");
            let cnonce = self.cnonce.as_deref().unwrap_or("");
            md5_hex(&format!(
                "{}:{}:{}:{}:auth:{}",
                ha1, self.nonce, nc, cnonce, ha2
            ))
        } else {
            md5_hex(&format!("{}:{}:{}", ha1, self.nonce, ha2))
        };
        constant_time_eq(expected.as_bytes(), self.response.as_bytes())
    }
}

/// タイミングサイドチャネル耐性のある等価判定。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// UAS 側で 401 にセットする `WWW-Authenticate` ヘッダ値を生成する。
///
/// RFC 7616 §3.3 (The WWW-Authenticate Response Header Field) に従い、
/// `stale` と `opaque` を含めて出力する。
///
/// - `nonce`: 呼び出し側で十分にランダムな値を渡すこと
///   (リプレイ防止のため `register::Registrar` 等のユーティリティ
///   `new_call_id` 相当で 64bit 以上を推奨)。
/// - `stale`: RFC 7616 §3.3:
///   > A case-insensitive flag indicating that the previous request from
///   > the client was rejected because the nonce value was stale. If stale
///   > is TRUE, the client may wish to simply retry the request with a new
///   > encrypted response, without re-prompting the user for a new
///   > username and password.
///
///   `true` を返すと UA は同じ credential のまま nonce だけ更新して再送する
///   (パスワード再入力ダイアログを出さない)。
/// - `opaque`: RFC 7616 §3.3:
///   > A string of data, specified by the server, that SHOULD be returned
///   > by the client unchanged in the Authorization header field of
///   > subsequent requests with URIs in the same protection space.
///
///   `None` の場合はパラメータ自体を出力しない (RFC 2617/7616 とも `opaque`
///   は SHOULD であり MUST ではない)。
///
/// 出力形式 (RFC 7616 §3.3 / RFC 2617 §3.2.1):
/// ```text
/// Digest realm="<realm>", nonce="<nonce>", algorithm=MD5,
///        qop="auth", stale=<true|false>[, opaque="<opaque>"]
/// ```
pub fn build_www_authenticate(
    realm: &str,
    nonce: &str,
    stale: bool,
    opaque: Option<&str>,
) -> String {
    build_authenticate_value(realm, nonce, stale, opaque)
}

/// UAS 側で 407 (`Proxy Authentication Required`) にセットする
/// `Proxy-Authenticate` ヘッダ値を生成する。
///
/// RFC 3261 §22.3 / RFC 7616 §3.3 に従い、`WWW-Authenticate` と同じ
/// パラメータ集合 (Digest scheme + realm/nonce/algorithm/qop/stale/opaque)
/// を返す。 ヘッダ名だけが異なる (proxy chain での再認可)。
pub fn build_proxy_authenticate(
    realm: &str,
    nonce: &str,
    stale: bool,
    opaque: Option<&str>,
) -> String {
    build_authenticate_value(realm, nonce, stale, opaque)
}

/// `WWW-Authenticate` / `Proxy-Authenticate` の値を組み立てる共通実装。
///
/// RFC 7616 §3.3 のパラメータ順序は規定されていないが、 既存 UA との互換のため
/// `realm, nonce, algorithm, qop, stale[, opaque]` の順で出力する。 `stale` は
/// RFC 7616 §3.3 の例にならい引用符無し (`stale=true` / `stale=false`)、
/// `opaque` は引用符付き (RFC 7616 §3.3: `opaque = "opaque" "=" quoted-string`)。
fn build_authenticate_value(realm: &str, nonce: &str, stale: bool, opaque: Option<&str>) -> String {
    let stale_str = if stale { "true" } else { "false" };
    let mut header = format!(
        r#"Digest realm="{}", nonce="{}", algorithm=MD5, qop="auth", stale={}"#,
        realm, nonce, stale_str
    );
    if let Some(o) = opaque {
        header.push_str(&format!(r#", opaque="{}""#, o));
    }
    header
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_parse() {
        let hdr = r#"Digest realm="ntt-east.ne.jp", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5, qop="auth""#;
        let c = DigestChallenge::parse(hdr).unwrap();
        assert_eq!(c.realm, "ntt-east.ne.jp");
        assert_eq!(c.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(c.qop, Some("auth".to_string()));
    }

    #[test]
    fn test_digest_compute_rfc2617_example() {
        // RFC 2617 の公式テストベクタ
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            algorithm: "MD5".to_string(),
            qop: Some("auth".to_string()),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
        };
        let creds = DigestCredentials::new("Mufasa", "Circle Of Life");
        // nc=1, cnonce は固定できないのでレスポンス計算が通ることだけ確認
        let resp = creds.compute(&challenge, "GET", "/dir/index.html", 1);
        assert!(!resp.header_value.is_empty());
    }

    /// クライアント側 compute → サーバ側 verify の往復テスト。
    /// `DigestCredentials` で組み立てた Authorization ヘッダを
    /// `DigestAuthorization` がパースし、同じパスワードで検証できる。
    #[test]
    fn test_digest_round_trip_qop_auth() {
        let challenge = DigestChallenge {
            realm: "sabiden".to_string(),
            nonce: "n0nce-12345".to_string(),
            algorithm: "MD5".to_string(),
            qop: Some("auth".to_string()),
            opaque: None,
        };
        let creds = DigestCredentials::new("iphone", "secret");
        let resp = creds.compute(&challenge, "REGISTER", "sip:sabiden", 1);
        let parsed = DigestAuthorization::parse(&resp.header_value).unwrap();
        assert!(parsed.verify("REGISTER", "secret"));
        assert!(!parsed.verify("REGISTER", "wrong"));
        // method 不一致では failed
        assert!(!parsed.verify("INVITE", "secret"));
    }

    #[test]
    fn test_digest_round_trip_no_qop() {
        let challenge = DigestChallenge {
            realm: "sabiden".to_string(),
            nonce: "n0nce-67890".to_string(),
            algorithm: "MD5".to_string(),
            qop: None,
            opaque: None,
        };
        let creds = DigestCredentials::new("android", "p@ss");
        let resp = creds.compute(&challenge, "INVITE", "sip:sabiden", 1);
        let parsed = DigestAuthorization::parse(&resp.header_value).unwrap();
        assert!(parsed.verify("INVITE", "p@ss"));
        assert!(!parsed.verify("INVITE", "wrong"));
    }

    #[test]
    fn test_build_www_authenticate_format() {
        let header = build_www_authenticate("sabiden", "abcdef", false, None);
        assert!(header.starts_with("Digest "));
        assert!(header.contains(r#"realm="sabiden""#));
        assert!(header.contains(r#"nonce="abcdef""#));
        assert!(header.contains("qop=\"auth\""));
    }

    #[test]
    fn test_authorization_parse_missing_field() {
        let bad = r#"Digest username="x", realm="y""#;
        assert!(DigestAuthorization::parse(bad).is_err());
    }

    /// RFC 7616 §3.3: `stale` flag は first-time challenge では false。
    /// 出力に `stale=false` が含まれること、 `opaque=None` のときは
    /// `opaque` パラメータが現れないことを確認する。
    #[test]
    fn rfc7616_3_3_www_authenticate_stale_false_no_opaque() {
        let header = build_www_authenticate("sabiden", "n0nce", false, None);
        assert!(header.starts_with("Digest "));
        assert!(header.contains("stale=false"));
        assert!(!header.contains("stale=true"));
        assert!(!header.contains("opaque="));
    }

    /// RFC 7616 §3.3: nonce が期限切れで再 challenge する場合は `stale=true`
    /// を立てる。 これにより UA は user に password 再入力させずに再送する。
    #[test]
    fn rfc7616_3_3_www_authenticate_stale_true() {
        let header = build_www_authenticate("sabiden", "n0nce", true, None);
        assert!(header.contains("stale=true"));
        assert!(!header.contains("stale=false"));
    }

    /// RFC 7616 §3.3: `opaque = "opaque" "=" quoted-string`. server-side
    /// token を quoted-string で出力する。
    #[test]
    fn rfc7616_3_3_www_authenticate_with_opaque() {
        let header = build_www_authenticate(
            "sabiden",
            "n0nce",
            false,
            Some("5ccc069c403ebaf9f0171e9517f40e41"),
        );
        assert!(header.contains(r#"opaque="5ccc069c403ebaf9f0171e9517f40e41""#));
        assert!(header.contains("stale=false"));
    }

    /// RFC 7616 §3.3 互換性: 生成した `WWW-Authenticate` を
    /// `DigestChallenge::parse` で読み戻して `realm` / `nonce` / `qop` /
    /// `opaque` が往復することを確認する。 `stale` は `DigestChallenge` の
    /// 既存フィールドに無いため (今回 issue 範囲外)、 文字列レベルでのみ確認する。
    #[test]
    fn rfc7616_3_3_www_authenticate_round_trip_via_digest_challenge() {
        let header =
            build_www_authenticate("ntt-east.ne.jp", "abc123", true, Some("opaque-token-xyz"));
        let parsed = DigestChallenge::parse(&header).unwrap();
        assert_eq!(parsed.realm, "ntt-east.ne.jp");
        assert_eq!(parsed.nonce, "abc123");
        assert_eq!(parsed.qop.as_deref(), Some("auth"));
        assert_eq!(parsed.opaque.as_deref(), Some("opaque-token-xyz"));
    }

    /// RFC 3261 §22.3 / RFC 7616 §3.3: `Proxy-Authenticate` は
    /// `WWW-Authenticate` と同じ Digest パラメータ集合を持つ (ヘッダ名のみ違う)。
    /// `build_proxy_authenticate` も同じ format を返すことを確認する。
    #[test]
    fn rfc3261_22_3_proxy_authenticate_format_matches_www() {
        let www = build_www_authenticate("sabiden", "n0nce", false, Some("op"));
        let proxy = build_proxy_authenticate("sabiden", "n0nce", false, Some("op"));
        assert_eq!(www, proxy);
        assert!(proxy.starts_with("Digest "));
        assert!(proxy.contains("stale=false"));
        assert!(proxy.contains(r#"opaque="op""#));
    }

    /// RFC 7616 §3.3: `stale` 値は case-insensitive flag だが、 RFC 例では
    /// `stale=TRUE` / `stale=true` の両表記が登場する。 sabiden は小文字
    /// (`true` / `false`) で出力する (RFC 7616 §3.3 の ABNF 例に倣う)。
    #[test]
    fn rfc7616_3_3_stale_values_are_lowercase_unquoted() {
        let h_true = build_www_authenticate("r", "n", true, None);
        let h_false = build_www_authenticate("r", "n", false, None);
        // 引用符無しで stale=true / stale=false が現れる
        assert!(h_true.contains("stale=true"));
        assert!(!h_true.contains(r#"stale="true""#));
        assert!(h_false.contains("stale=false"));
        assert!(!h_false.contains(r#"stale="false""#));
    }
}
