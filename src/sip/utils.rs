use rand::Rng;

pub fn new_branch() -> String {
    let r: u64 = rand::thread_rng().gen();
    format!("z9hG4bK{:016x}", r)
}

pub fn new_call_id() -> String {
    let r: u64 = rand::thread_rng().gen();
    format!("{:016x}@hikari-sip", r)
}

pub fn new_tag() -> String {
    let r: u32 = rand::thread_rng().gen();
    format!("{:08x}", r)
}

/// `To:` ヘッダ値に `tag=` パラメータが付いているかを判定する。
///
/// RFC 3261 §14.2 / §12.2.2: 受信 INVITE の To に tag が付いている場合は
/// in-dialog Re-INVITE (既存 dialog 内 SDP renegotiation 要求) であり、
/// 新規 INVITE (To-tag 無し = dialog-creating) と扱いが異なる。 また
/// RFC 3261 §8.2.6.2 で UAS が応答に tag を付与する判定にも使う
/// (= 既存 tag があれば二重付与してはならない)。
///
/// `;` で分割した各パラメータを `tag=` プレフィックスで判定する
/// (`tag=` を含む URI 値部分 (`<sip:user;tag-x@host>` のような) を誤検出
/// しないように、 `<...>` 内の `;` は無視する)。
///
/// パラメータ名 (`tag`) は **case-insensitive** に比較する
/// (RFC 3261 §7.3.1 / §25.1: header parameter name は token であり、
/// token の比較は大文字小文字を区別しない)。 そのため `;Tag=`、 `;TAG=` 等
/// も「tag 付き」として扱う。 値部分は token 比較ではなく原文を保持するが、
/// ここでは「空でないか」だけ検査する。
///
/// この関数は in-dialog 判定 (`src/sip/uas.rs::handle_invite`) と、
/// レスポンス To-tag 二重付与防止 (`ensure_to_tag` in `src/sip/uas.rs` /
/// `src/call/orchestrator.rs`) の両方で利用される。 単一情報源にすることで
/// case-sensitivity が片側だけ抜け落ち `;TAG=existing;tag=new` のような
/// 二重 tag を返してしまう RFC 3261 §12.2.2 違反を防ぐ。
pub fn has_to_tag(value: &str) -> bool {
    // RFC 3261 §20.10: To = ( name-addr / addr-spec ) *( SEMI to-param )
    // name-addr の山括弧 `<...>` 内には任意のセミコロンが現れるが、
    // ヘッダパラメータとしての `;tag=` は山括弧の **外** にしか出ない。
    let mut depth = 0i32;
    let mut after_semi = false;
    let mut start = 0usize;
    let bytes = value.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b';' if depth == 0 => {
                if after_semi && param_is_nonempty_tag(value[start..i].trim()) {
                    return true;
                }
                after_semi = true;
                start = i + 1;
            }
            _ => {}
        }
    }
    if after_semi && param_is_nonempty_tag(value[start..].trim()) {
        return true;
    }
    false
}

/// `tag=<value>` (パラメータ名 case-insensitive、 値非空) かを判定する。
///
/// RFC 3261 §7.3.1 / §25.1: header parameter name は token として
/// case-insensitive 比較。 値 (token) は仕様上 case-sensitive だが、
/// ここでは "tag が付いているか" だけが必要なので空チェックのみ。
fn param_is_nonempty_tag(param: &str) -> bool {
    let Some(eq_idx) = param.find('=') else {
        return false;
    };
    let name = &param[..eq_idx];
    let value = &param[eq_idx + 1..];
    name.eq_ignore_ascii_case("tag") && !value.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 3261 §20.10 / §7.3.1 / §25.1 / Issue #94 / PR #136 review:
    /// To ヘッダの tag パラメータ抽出は `tag=` を含む URI ユーザ部などを
    /// 誤検出してはならず、 また parameter name (`tag`) は **case-insensitive**
    /// 比較である。
    #[test]
    fn rfc3261_20_10_has_to_tag_detects_top_level_tag_only() {
        // 通常の Re-INVITE 形式: name-addr + ;tag=
        assert!(has_to_tag("<sip:dest@sabiden>;tag=abc123"));
        // addr-spec + ;tag=
        assert!(has_to_tag("sip:dest@sabiden;tag=xyz"));
        // 新規 INVITE: tag 無し
        assert!(!has_to_tag("<sip:dest@sabiden>"));
        assert!(!has_to_tag("sip:dest@sabiden"));
        // 山括弧内に `tag=` 文字列が含まれていても誤検出しない
        // (URI userinfo / params が tag= と命名されているケース対策)
        assert!(!has_to_tag("<sip:dest;tag=fake@sabiden>"));
        // tag= の値が空なら無効扱い (RFC 3261 §19.3 token 必須)
        assert!(!has_to_tag("<sip:dest@sabiden>;tag="));
        // display-name 入りでも先頭 `<` の前に `;tag=` は出ない (構文上)。
        // 例: `"alice" <sip:a@b>;tag=t1`
        assert!(has_to_tag("\"alice\" <sip:a@b>;tag=t1"));
        // RFC 3261 §7.3.1 / §25.1: parameter name は case-insensitive。
        // `Tag=` `TAG=` `tAg=` 等も 「tag 付き」 として認識する必要がある。
        assert!(has_to_tag("<sip:dest@sabiden>;Tag=abc"));
        assert!(has_to_tag("<sip:dest@sabiden>;TAG=abc"));
        assert!(has_to_tag("<sip:dest@sabiden>;tAg=abc"));
        // 別パラメータ後の混在も正しく検出する
        assert!(has_to_tag("<sip:dest@sabiden>;user=phone;Tag=abc"));
        // `tag` で始まるが別名のパラメータ (`tagx=`) は検出しない
        assert!(!has_to_tag("<sip:dest@sabiden>;tagx=abc"));
        assert!(!has_to_tag("<sip:dest@sabiden>;TAGGED=abc"));
    }
}
