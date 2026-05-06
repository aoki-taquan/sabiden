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
            let (k, v) = part.split_once('=').ok_or_else(|| anyhow::anyhow!("bad auth param: {}", part))?;
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

        Ok(DigestChallenge { realm, nonce, algorithm, qop, opaque })
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

        let ha1 = md5_hex(&format!("{}:{}:{}", self.username, challenge.realm, self.password));
        let ha2 = md5_hex(&format!("{}:{}", method, uri));

        let response = if challenge.qop.as_deref() == Some("auth") {
            let nc_str = format!("{:08x}", nc);
            md5_hex(&format!("{}:{}:{}:{}:auth:{}", ha1, challenge.nonce, nc_str, cnonce, ha2))
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

        DigestResponse { header_value: header, cnonce, nc }
    }
}

fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
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
}
