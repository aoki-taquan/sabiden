#!/usr/bin/env bash
# WebRTC シグナリング用 HMAC-SHA256 トークンを発行する。
# 形式 (src/webrtc/auth.rs と一致):
#   <ext_id>.<expiry_unix>.<base64url(hmac-sha256(secret_hex, "ext_id.expiry_unix"))>
#
# usage: scripts/dev-token.sh <ext_id> [ttl_seconds] [secret_hex_or_path]
#   - ext_id: 仮想内線名 (例: webrtc-alice)
#   - ttl_seconds: 有効期限 (既定 3600)
#   - secret_hex_or_path: 16 進共有秘密 or それを書いたファイル。
#                        省略時は config.toml の `secret_hex` を抽出。
set -euo pipefail

ext_id="${1:?ext_id required}"
ttl="${2:-3600}"
secret_arg="${3:-}"

if [[ -z "${secret_arg}" ]]; then
    cfg="$(dirname "$0")/../config.toml"
    secret_hex=$(awk -F'"' '/^secret_hex *=/{print $2; exit}' "${cfg}")
elif [[ -f "${secret_arg}" ]]; then
    secret_hex=$(cat "${secret_arg}")
else
    secret_hex="${secret_arg}"
fi

[[ -n "${secret_hex}" ]] || { echo "secret_hex 未取得" >&2; exit 1; }

expiry=$(( $(date +%s) + ttl ))
msg="${ext_id}.${expiry}"
sig=$(printf '%s' "${msg}" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${secret_hex}" -binary \
    | base64 \
    | tr -d '=' \
    | tr '+/' '-_')

printf '%s.%s\n' "${msg}" "${sig}"
