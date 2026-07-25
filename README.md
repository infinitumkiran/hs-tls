# euler-tls-traced — call-traced forks of the outbound TLS stack

*Lives on the `traced-forks` branch of `github:infinitumkiran/hs-tls` (an
unrelated history to that repo's other branches, which it does not touch), and
locally in `euler-api-gateway/forks/euler-tls-traced`. euler-api-gateway pins it
as the `hs-tls-traced` flake input.*

Debug forks of the packages euler-api-gateway's outbound HTTPS path goes through.
Every top-level function is wrapped so that entering and leaving it is printed.
The point is to answer one question: **which function does a failing request die
in?**

> **Not for production and not for upstream.** These forks exist to locate a
> break. Once the breaking function is known, fix it properly and drop the pin.

## Packages

Each is the pristine Hackage release that `dist-newstyle/cache/plan.json`
resolves for the `ghc984` branch, plus tracing. The first commit in this repo is
the untouched sdist, so `git show` / `git diff` against it is exactly the
instrumentation and nothing else.

| subdir                     | version  | instrumented                       |
|----------------------------|----------|------------------------------------|
| `tls/`                     | 1.9.0    | all 59 library modules             |
| `crypton/`                 | 1.0.4    | the 33 modules the TLS path imports |
| `crypton-x509/`            | 1.7.7    | all                                |
| `crypton-x509-store/`      | 1.6.11   | all                                |
| `crypton-x509-validation/` | 1.6.14   | all                                |
| `crypton-x509-system/`     | 1.6.7    | all                                |
| `crypton-connection/`      | 0.4.5    | all                                |
| `http-client/`             | 0.7.19   | all except the public-suffix data table |
| `http-client-tls/`         | 0.3.6.4  | all                                |
| `ett-probe/`               | —        | standalone one-request repro tool  |

`crypton-x509-system` was not on the original list but is included: overriding
`crypton-x509` forces it to be rebuilt anyway, and it is on the TLS path — it is
what loads the system CA store.

`crypton` is deliberately partial: instrumenting all 201 modules means tracing
every AES block and hash update, which buries the signal and slows a repro to a
crawl. The 33 modules kept are the ones `tls`, `crypton-x509*`,
`crypton-connection` and `http-client-tls` actually import.

## Turning it on

Tracing is off unless the environment says otherwise, so an instrumented build
behaves like a normal one:

```bash
EULER_TLS_TRACE=all                         # every package
EULER_TLS_TRACE=tls,crypton-connection      # only these
```

Package names are the subdir names above.

The trace goes to **stderr**; redirect it yourself:

```bash
EULER_TLS_TRACE=all euler-api-gateway 2>>/tmp/tls-trace.log
```

The tracer deliberately never opens a log file of its own. Each package carries
its own copy of the tracer module, and GHC takes a per-inode write lock, so only
the first package to open a shared file would get a handle — the other eight
would silently trace nothing. (`ett-probe` does accept
`EULER_TLS_TRACE_FILE=...`: it redirects its own stderr, which is safe because
there is exactly one redirect.)

Expect roughly **12k lines per HTTPS request** with `EULER_TLS_TRACE=all`
(measured: crypton 4.7k, crypton-x509 4.8k, tls 1.9k, the rest smaller). Narrow
with `EULER_TLS_TRACE=tls,crypton-connection,http-client` when you already know
the failure is at the protocol layer rather than in cert parsing.

## Reading the output

```
ETT <seq> <pkg> <threadid> <indent><dir> <label>
```

| `dir` | meaning |
|-------|---------|
| `>`   | entered (paired with a `<` or `!`) |
| `<`   | returned normally |
| `!`   | left via an exception — the exception is appended after `!!` |
| `:`   | entered, exit not tracked (see below) |

**The innermost `>` with no matching `<` is the function that broke.** `seq` is a
global counter, so you can sort a multi-threaded log deterministically, and diff
two runs (e.g. working host vs. failing host) to find where they diverge.

`tools/ett-blame.py` does that reading for you:

```
$ python3 tools/ett-blame.py trace.log
1069 trace events

>>> BROKE IN: Network.TLS.Packet.getHeaderType   (tls, seq 366)
    Uncontextualized (Error_Packet_Parsing "Failed reading: invalid header type: 72 ...")

    entry-only frames just before it (any of these may be the
    actual thrower -- pure functions have no exit line):
      tls                      Network.TLS.Packet.decodeHeader
      tls                      Network.TLS.Wire.runGetErr
      tls                      Network.TLS.Context.Internal.throwCore

exception propagated out through:
  tls                      Network.TLS.Handshake.Common.runRecvState
  tls                      Network.TLS.Handshake.Client.handshakeClient
  ...
  crypton-connection       Network.Connection.tlsEstablish
  http-client              Network.HTTP.Client.Core.httpLbs
```

That is a real run — `ett-probe https://example.com:80/`, i.e. TLS against a
plain-HTTP port. `getHeaderType` is the function that rejected record header byte
72, the `H` of `HTTP/1.1`. Note that it reports the state **at the first `!`**,
not at the end of the trace: by the end every frame has been unwound, so the
end state is empty and tells you nothing.

To compare a host that works against one that does not:

```bash
python3 tools/ett-blame.py --diff good.log bad.log
```

## Why some functions only print entry

Three wrappers are injected, picked from the function's own type signature:

| wrapper | applies to | prints |
|---------|-----------|--------|
| `tio`   | result is `IO a` | entry, exit, exception |
| `tm`    | result is `m a` with a `Monad`-implying constraint, or a known concrete monad | entry, exit |
| `t`     | everything else — pure functions, and anything whose result type could not be proven monadic | entry |

`t` is `Debug.Trace.trace`-shaped (`String -> a -> a`), so it type-checks against
any right-hand side; that is what makes "every function" achievable without
hand-editing thousands of definitions. But nothing of that type can observe a
return, so pure functions get entry only. There is no exception line outside
`IO` either — a `tm` frame that fails shows up as a `>` with no `<`, which is
still the signal you need.

Counts: 276 `tio`, 322 `tm`, 1558 `t` across 133 files.

One more caveat: the indentation is best-effort. A `tm` frame's exit line only
prints when the wrapped action's result is forced, so in a lazy monad a few exits
never fire and the per-thread depth counter drifts. Pairing is by **label**, not
by indent, so this is cosmetic — `ett-blame.py` ignores indentation entirely.

Note that `t` fires when the right-hand side is **forced**, not when the function
is applied. For a lazy pure function that is usually the same moment; for one
whose result is never demanded, the line may not appear at all.

## Repro tool

`ett-probe` makes a single request through this exact stack, which is much faster
to iterate on than booting the gateway:

```bash
cabal run ett-probe -- https://juspay.3ds-server.prev.netcetera-cloud-payment.ch/3ds/authentication
```

with `EULER_TLS_TRACE=all` set. `ETT_PROBE_TLS12=1` offers TLS 1.2 only, which is
option A in the gateway's `TLS_2x_MIGRATION.md`; `ETT_PROBE_METHOD=POST` changes
the method.

## Pinning it into euler-api-gateway

`traceTls = true;` at the top of `nix/haskell-project.nix`. That is the whole
switch -- the flake input is already pinned. After changing the instrumentation:

```bash
git push origin main:traced-forks
cd <euler-api-gateway> && nix flake lock --override-input hs-tls-traced \
    github:infinitumkiran/hs-tls/$(git -C forks/euler-tls-traced rev-parse HEAD)
```

Note the sources are pinned with `lib.mkForce`: `packages.tls.source` is also
defined by the euler-webservice project module, and nix module options *merge*
rather than override, so without `mkForce` the two definitions are a conflict.

## Regenerating

The instrumentation is mechanical, not hand-written, so it can be re-applied to
a different version. `tools/` holds the rewriter:

```bash
python3 tools/build_forks.py <dest>     # downloads sdists, injects, writes the tree
```

To move to a different upstream version, edit the `PKGS` table at the top of
`build_forks.py` (each entry is sdist name, subdir, package tag, tracer module
name, excluded module prefixes) and re-run.

The rewriter turns `f a b = RHS` into `f a b = ETT__.t "Mod.f" ETT__.$ RHS`,
one injection per clause and per guard alternative. When the right-hand side
opens a layout block whose first item is on the same line, every continuation
line of that clause is shifted by the same width so the layout is preserved.

## Overhead when disabled

One `Bool` test per call against a `NOINLINE` CAF, plus a lost inlining
opportunity at each wrapped definition. Fine for a staging repro; do not ship it.
