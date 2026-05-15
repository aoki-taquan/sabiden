//! WebRTC シグナリング用の HMAC-SHA256 トークン認証
//!
//! ブラウザは WebSocket ハンドシェイク時に `Authorization: Bearer <token>`
//! または `?token=<token>` クエリで HMAC トークンを提示する。
//!
//! # トークン形式
//!
//! `<ext_id>.<expiry_unix>.<base64url(hmac-sha256(secret, ext_id|expiry_unix))>`
//!
//! - `ext_id`: 仮想内線アカウント名 (例: `webrtc-alice`)
//! - `expiry_unix`: 有効期限の Unix 秒 (10 進数)
//! - 署名: HMAC-SHA256(secret, "<ext_id>.<expiry_unix>") の URL-safe base64
//!
//! 設計判断:
//! - JWT を採用しなかったのは、サブセットのフィールド (sub + exp) 以上は
//!   不要であり、依存を増やさないため。Cloudflare Zero Trust 連携が
//!   必要になったら `jsonwebtoken` を別 PR で導入する (Issue 残)。
//! - 比較は [`subtle::ConstantTimeEq`] でタイミング攻撃を避ける。

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// 検証成功時に返す主クレーム。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthClaims {
    /// 仮想内線アカウント名 (内線 registrar に登録される AOR)。
    pub ext_id: String,
    /// 期限切れの Unix 秒。
    pub expiry: u64,
}

/// トークン検証エラー。
#[derive(Debug)]
pub enum AuthError {
    /// `<ext_id>.<expiry>.<sig>` の三分割に失敗。
    Malformed,
    /// expiry が数値として解釈できない。
    BadExpiry,
    /// 署名が一致しない。
    BadSignature,
    /// 期限切れ。
    Expired,
    /// 署名の base64 デコードに失敗。
    BadEncoding,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Malformed => write!(f, "malformed token"),
            AuthError::BadExpiry => write!(f, "bad expiry"),
            AuthError::BadSignature => write!(f, "bad signature"),
            AuthError::Expired => write!(f, "token expired"),
            AuthError::BadEncoding => write!(f, "bad encoding"),
        }
    }
}

impl std::error::Error for AuthError {}

/// HMAC 検証器。共有秘密鍵と現在時刻クロックを束ねる。
///
/// テストでは `Self::with_now` (cfg=test) で時計を注入できる。
pub struct Verifier {
    secret: Vec<u8>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl Verifier {
    /// 共有秘密鍵で初期化。`secret` は最低 16 バイト推奨。
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        Self {
            secret: secret.into(),
            now: Box::new(default_now),
        }
    }

    /// テスト用: 時計を差し替える。
    #[cfg(test)]
    pub fn with_now(mut self, now: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.now = Box::new(now);
        self
    }

    /// 与えられたトークンを検証して [`AuthClaims`] を返す。
    pub fn verify(&self, token: &str) -> Result<AuthClaims, AuthError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::Malformed);
        }
        let ext_id = parts[0];
        let expiry_str = parts[1];
        let sig_b64 = parts[2];
        if ext_id.is_empty() {
            return Err(AuthError::Malformed);
        }
        let expiry: u64 = expiry_str.parse().map_err(|_| AuthError::BadExpiry)?;

        // 期限チェックは署名前に行う。期限切れトークンの署名は計算するだけ無駄。
        if (self.now)() >= expiry {
            return Err(AuthError::Expired);
        }

        let signed = format!("{}.{}", ext_id, expiry);
        let expected = self.sign_bytes(signed.as_bytes());
        let actual = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| AuthError::BadEncoding)?;
        if expected.ct_eq(&actual).into() {
            Ok(AuthClaims {
                ext_id: ext_id.to_string(),
                expiry,
            })
        } else {
            Err(AuthError::BadSignature)
        }
    }

    /// 与えられたメッセージに HMAC-SHA256 を計算する (テスト/トークン発行用)。
    pub fn sign_bytes(&self, msg: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key size");
        mac.update(msg);
        mac.finalize().into_bytes().to_vec()
    }

    /// `(ext_id, expiry)` から本検証器に対応するトークンを発行する (テスト用)。
    pub fn issue(&self, ext_id: &str, expiry: u64) -> String {
        let signed = format!("{}.{}", ext_id, expiry);
        let sig = self.sign_bytes(signed.as_bytes());
        format!("{}.{}", signed, URL_SAFE_NO_PAD.encode(sig))
    }
}

fn default_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_then_verify_round_trip() {
        let v = Verifier::new(b"super-secret".to_vec()).with_now(|| 1_000);
        let token = v.issue("alice", 2_000);
        let claims = v.verify(&token).unwrap();
        assert_eq!(claims.ext_id, "alice");
        assert_eq!(claims.expiry, 2_000);
    }

    #[test]
    fn rejects_expired_token() {
        let v = Verifier::new(b"x".to_vec()).with_now(|| 5_000);
        let token = v.issue("bob", 1_000);
        let err = v.verify(&token).unwrap_err();
        assert!(matches!(err, AuthError::Expired));
    }

    #[test]
    fn rejects_tampered_token() {
        let signer = Verifier::new(b"k1".to_vec()).with_now(|| 1);
        let token = signer.issue("alice", 9_999);
        // 別の鍵で検証 → 署名不一致
        let other = Verifier::new(b"k2".to_vec()).with_now(|| 1);
        assert!(matches!(
            other.verify(&token).unwrap_err(),
            AuthError::BadSignature
        ));
    }

    #[test]
    fn rejects_malformed_token() {
        let v = Verifier::new(b"k".to_vec());
        assert!(matches!(
            v.verify("nope").unwrap_err(),
            AuthError::Malformed
        ));
        assert!(matches!(
            v.verify(".1234.sig").unwrap_err(),
            AuthError::Malformed
        ));
    }

    #[test]
    fn rejects_bad_expiry() {
        let v = Verifier::new(b"k".to_vec());
        assert!(matches!(
            v.verify("alice.notanumber.sig").unwrap_err(),
            AuthError::BadExpiry
        ));
    }

    #[test]
    fn rejects_bad_base64() {
        let v = Verifier::new(b"k".to_vec()).with_now(|| 1);
        assert!(matches!(
            v.verify("alice.9999.!!!").unwrap_err(),
            AuthError::BadEncoding
        ));
    }
}
