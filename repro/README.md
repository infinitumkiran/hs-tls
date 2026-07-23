# tls-repro — live repro of the TLS 1.3 `recvData`-on-close HTTP 500

Reproduces the production error

```
InternalException data: end of file      (HTTP 500)
```

against any live TLS 1.3 endpoint that sends a `close_notify` after its
response (e.g. `www.google.com`, `www.cloudflare.com`) — at the TLS layer, with
**no http-client, no 3DS server, and no deploy**.

## Run

From the repo root:

```sh
nix develop ./tls --option allow-import-from-derivation true \
  -c bash -c "cd repro && cabal run -v0 tls-repro -- www.google.com 443 1.3"
```

Expected output:

| `tls/Network/TLS/Core.hs` `recvData` | output |
|---|---|
| **FIXED** (returns `""` when `ctxEOF`) | `RESULT: recvData => ""   graceful EOF  => http-client HTTP 200   [FIXED]` |
| **BROKEN** (revert the `eofed` short-circuit) | `RESULT: recvData THREW: data: end of file  => http-client InternalException => HTTP 500   [BROKEN]` |

To see the BROKEN case, temporarily revert `recvData` in
`tls/Network/TLS/Core.hs` to `checkValid ctx >> (if tls13 then recvData13 ctx
else recvData12 ctx)`, rebuild, and rerun; then `git checkout` the file.

## Why this is the whole bug

`recvData` returning `""` vs. throwing is exactly what `crypton-connection`'s
`connectionGetChunkBase` keys off of on every response-body read:

```haskell
chunk <- TLS.recvData tlsctx
if B.null chunk then <clean EOF>   -- "" => http-client HTTP 200
                else ...
```

A thrown exception propagates up and `http-client` wraps it as
`HttpExceptionContent.InternalException` → HTTP 500. A TLS 1.3 peer sends
`close_notify` right after its response, so the caller's next read hits an
already-closed context; before the fix that read threw, after the fix it
returns `""`.

## What the program does

1. TLS handshake (forced to the requested version), accepting any cert.
2. Sends `GET / HTTP/1.1` with `Connection: close`.
3. `recvData` until it returns `""` (server closed).
4. One more `recvData` on the closed context — the read that http-client makes,
   and the one that used to throw.
