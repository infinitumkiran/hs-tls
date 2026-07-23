#!/usr/bin/env bash
#
# Real-peer interop test for the backward-compatibility feature.
#
# Points the (patched) tls-simpleclient at badssl.com's public endpoints that
# still serve legacy TLS versions and ciphers -- something no ordinary host
# does any more, and something OpenSSL 3.0 itself can no longer do for RC4/3DES.
#
# Requires: a built tls-simpleclient (debug package) with the ciphersuite_backwardCompat
# patch, and network access to badssl.com.
#
# Usage:  ./test-scripts/interop-legacy.sh
set -u

CLIENT="cabal run -v0 tls-simpleclient --"   # or: path to the built binary
TIMEOUT="${TIMEOUT:-20}"

# label | flags | host | port
CASES=(
  "TLS 1.0 (ECDHE-RSA-AES256-CBC-SHA)|--tls10|tls-v1-0.badssl.com|1010"
  "TLS 1.1 (ECDHE-RSA-AES256-CBC-SHA)|--tls11|tls-v1-1.badssl.com|1011"
  "TLS 1.2 (AEAD, sanity)             |--tls12|tls-v1-2.badssl.com|1012"
  "TLS 1.2 + CBC                      |--tls12|cbc.badssl.com|443"
  "TLS 1.2 + RC4                      |--tls12|rc4.badssl.com|443"
  "TLS 1.2 + RC4-MD5                  |--tls12|rc4-md5.badssl.com|443"
  "TLS 1.2 + 3DES                     |--tls12|3des.badssl.com|443"
)

pass=0; fail=0
printf '%-40s %s\n' "CASE" "RESULT"
printf '%-40s %s\n' "----" "------"
for c in "${CASES[@]}"; do
  IFS='|' read -r label flags host port <<<"$c"
  # -d prints the handshake so we can see the negotiated version/cipher.
  out=$(timeout "$TIMEOUT" $CLIENT "$flags" --no-validation -d "$host" "$port" 2>&1)
  rc=$?
  neg=$(printf '%s\n' "$out" | grep -iE "ServerHello|version|cipher" | head -1 | tr -s ' ')
  if [ $rc -eq 0 ]; then
    printf '%-40s \033[32mPASS\033[0m  %s\n' "$label" "$neg"; pass=$((pass+1))
  else
    printf '%-40s \033[31mFAIL(%d)\033[0m %s\n' "$label" "$rc" \
      "$(printf '%s\n' "$out" | grep -iE 'exception|error|fail' | head -1)"; fail=$((fail+1))
  fi
done
echo
echo "passed: $pass   failed: $fail"
[ $fail -eq 0 ]
