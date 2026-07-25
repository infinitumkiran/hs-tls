-- | Lightweight wire/handshake tracing used to diagnose connection failures
-- (e.g. a peer that closes right after the handshake with no application data,
-- surfacing to http-client as @NoResponseDataReceived@).
--
-- All output is a single stdout line prefixed with @[TLS-DBG]@, then a
-- monotonic timestamp and the emitting thread id:
--
-- > [TLS-DBG] t=<monotonic ns> tid=<ThreadId> <message>
--
-- The thread id is the cross-package join key: http-client runs one request on
-- one thread, so the handshake, the crypton signing, the x509 parsing and the
-- socket calls belonging to that request all carry the same @tid@ and can be
-- separated from the unrelated TLS traffic sharing the log.  The monotonic
-- clock makes the ~1 RTT gap between the client Finished and the peer's FIN
-- directly measurable instead of inferred.
--
-- Tracing is unconditionally ON in this fork: it reads no environment
-- variables, so a deployment gets the full trace with no configuration.  This
-- is a debugging build -- expect a high log volume, including a per-packet
-- trace for every TLS connection the process opens (unrelated AWS/KMS traffic
-- included).  To quieten it later, flip 'tlsDebugEnabled' (all tracing) or
-- 'tlsDebugVerbose' (just the per-packet/record firehose, keeping the targeted
-- handshake lines) to 'False' and rebuild.
--
-- == Safety contract
--
-- This module runs inside a payments service, so the tracing must be inert:
--
--   * It never throws a synchronous exception at its caller.  Every entry
--     point ('tlsDebug', 'tlsDebugV', 'tlsDebugHost', 'tlsDebugSafeIO') runs
--     its whole body -- including the rendering of the message -- inside a
--     'ForkLogE.SomeException' handler.
--   * It never swallows an /asynchronous/ exception.  @timeout@ (used by
--     "Network.TLS.Core"'s post-handshake client-auth check) and
--     'Control.Concurrent.killThread' deliver 'ForkLogE.SomeAsyncException' /
--     'ForkLogE.AsyncException'; those are re-thrown unchanged so the host's
--     cancellation semantics are preserved.
--   * It never hangs on a runaway renderer: the fully rendered line is
--     truncated to 'forkLineCharCap' characters, and the truncation is
--     performed lazily so an infinite string is cut rather than forced.
--   * It stays cancellable when stdout backs up.  A single @write(2)@ larger
--     than @PIPE_BUF@ blocks inside a @safe@ foreign call, where no
--     asynchronous exception can reach it -- so one oversized trace line would
--     wedge a request thread past the reach of @timeout@ and
--     'Control.Concurrent.killThread'.  Long lines are therefore split into
--     physical writes of at most 'forkWriteChunkChars' characters.
--   * It never depends on the pod's locale: 'forkAsciiOnly' escapes every
--     character outside printable ASCII before the write.
--
-- This module is compiled with @Strict@ (see @default-extensions@ in
-- @tls.cabal@), which makes every function parameter and @let@ binding strict.
-- The @~@ patterns on the message arguments below are therefore load-bearing:
-- without them the message thunk would be forced /on entry/, i.e. outside the
-- handler, and a bottom inside an interpolated value would escape into the
-- instrumented code path.  Do not remove them.
module Network.TLS.DebugLog (
    tlsDebugEnabled,
    tlsDebug,
    tlsDebugVerbose,
    tlsDebugV,
    tlsDebugHost,
    tlsDebugHostFilter,
    tlsDebugSafeIO,
    hexOf,
) where

import qualified Control.Concurrent as ForkLogC
import qualified Control.Exception as ForkLogE
import Control.Monad (when)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as C8
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import Data.Maybe (isJust)
import qualified GHC.Clock as ForkLogClock
import qualified System.IO as ForkLogIO
import System.IO.Unsafe (unsafePerformIO)

-- | Whether tracing is emitted at all.  Always on in this fork.
tlsDebugEnabled :: Bool
tlsDebugEnabled = True

-- | True if the given SNI/host should be traced.  Every host passes.
tlsDebugHostFilter :: String -> Bool
tlsDebugHostFilter _ = True

-- | Whether the high-volume packet\/record trace is emitted.  Kept as a
-- separate switch from 'tlsDebugEnabled' so the firehose can be turned off
-- independently of the targeted handshake traces, which are only a handful of
-- lines per connection.  Always on in this fork.
tlsDebugVerbose :: Bool
tlsDebugVerbose = True

----------------------------------------------------------------
-- (fork) Exception discipline
----------------------------------------------------------------

-- | Is this an /asynchronous/ exception, i.e. one delivered by another thread
-- (@throwTo@) rather than raised by the code we are running?
--
-- Both spellings are checked.  Everything thrown by 'ForkLogC.killThread' and
-- by @System.Timeout.timeout@ has an 'ForkLogE.Exception' instance built on
-- @asyncExceptionToException@, so the 'ForkLogE.SomeAsyncException' test alone
-- would in fact suffice; 'ForkLogE.AsyncException' is checked as well so that a
-- 'ForkLogE.ThreadKilled' or 'ForkLogE.StackOverflow' that reached us in the
-- bare form is still recognised.
forkIsAsyncException :: ForkLogE.SomeException -> Bool
forkIsAsyncException e = isJust (asSomeAsync e) || isJust (asAsync e)
  where
    asSomeAsync :: ForkLogE.SomeException -> Maybe ForkLogE.SomeAsyncException
    asSomeAsync = ForkLogE.fromException
    asAsync :: ForkLogE.SomeException -> Maybe ForkLogE.AsyncException
    asAsync = ForkLogE.fromException

-- | Run an instrumentation-only action: swallow every synchronous failure,
-- re-throw every asynchronous one.
--
-- Swallowing is what keeps a broken trace from killing the host; re-throwing is
-- what keeps the logger from silently defeating @timeout@ and @killThread@.
-- Nothing here is allowed to alter the result of the caller, so the action is
-- @IO ()@ by construction.
--
-- The @~@ on the argument matters under @Strict@: forcing the action thunk on
-- entry would happen before the handler is installed.
forkSwallowSync :: IO () -> IO ()
forkSwallowSync ~act = do
    r <- ForkLogE.try act
    case (r :: Either ForkLogE.SomeException ()) of
        Right () -> return ()
        Left e
            | forkIsAsyncException e -> ForkLogE.throwIO e
            | otherwise -> return ()

-- | Public wrapper for instrumentation-only 'IO' performed at a call site --
-- an extra state read done purely to enrich a trace, for instance.  Such code
-- must be as inert as the emit itself: 'forkSwallowSync' gives it the same
-- \"synchronous failures vanish, asynchronous failures propagate\" contract.
tlsDebugSafeIO :: IO () -> IO ()
tlsDebugSafeIO ~act = when tlsDebugEnabled $ forkSwallowSync act

----------------------------------------------------------------
-- (fork) Total, encoding-safe, bounded line emitter
----------------------------------------------------------------

-- Two faults took the application down in production; both are fixed here.
--
--   * A container with no LANG set gives stdout an ASCII encoding.  A
--     certificate subject holding a non-ASCII character -- e.g. the Hungarian
--     NetLock CA in /etc/ssl/certs/ca-bundle.crt -- then makes 'putStrLn' fail
--     mid-write with @commitBuffer: invalid argument@, leaving a truncated
--     line.  'forkAsciiOnly' escapes everything outside printable ASCII, so the
--     write no longer depends on the pod's locale.
--
--   * That exception escaped the logger and propagated through the very code
--     being instrumented, killing the process.  A logger must never change the
--     behaviour of the program it observes, so synchronous failures are
--     swallowed here.

-- | Hard cap on the number of characters written for one trace line, applied
-- after ASCII escaping.
--
-- This is the backstop that makes every renderer in the package bounded
-- whatever it is handed: a peer-controlled @certificate_authorities@ list or
-- @signature_algorithms@ list can hold tens of thousands of entries, and a
-- renderer fed a cyclic or infinite structure would otherwise make the forcing
-- step below loop forever -- a hang, which is worse than a crash.  The cap is
-- large enough to keep the biggest deliberate trace (the 65536-character
-- certificate-message dump in "Network.TLS.Hooks") intact.
forkLineCharCap :: Int
forkLineCharCap = 262144

-- | @take@ that reports truncation and never forces more of its argument than
-- the cap allows.  Lazy in the tail by construction, so an infinite input is
-- cut instead of diverging.
forkTakeCapped :: Int -> String -> String
forkTakeCapped n0 s0 = go n0 s0
  where
    go _ [] = []
    go n (c : cs)
        | n <= 0 = "...<truncated at TLS-DBG line cap>"
        | otherwise = c : go (n - 1) cs

-- | Escape to printable ASCII.  Lazy, so 'forkTakeCapped' can stop it early.
forkAsciiOnly :: String -> String
forkAsciiOnly = concatMap esc
  where
    esc c
        | c == '\n' || c == '\r' || c == '\t' = " "
        | c >= ' ' && c <= '~' = [c]
        | otherwise =
            let n = fromEnum c
             in if n <= 0xFF
                    then ['\\', 'x', hx (n `div` 16), hx (n `mod` 16)]
                    else
                        [ '\\'
                        , 'u'
                        , hx ((n `div` 4096) `mod` 16)
                        , hx ((n `div` 256) `mod` 16)
                        , hx ((n `div` 16) `mod` 16)
                        , hx (n `mod` 16)
                        ]
    -- Total by construction: no '!!', no incomplete match.  Every caller passes
    -- a value that is already in [0,15], but a renderer must not depend on that
    -- being true.
    hx k = case drop k "0123456789abcdef" of
        (d : _) -> d
        [] -> '?'

-- | Render one line: escape, cap, then force completely.
--
-- Forcing before the write is what stops a bottom inside an interpolated value
-- from producing a half-written line; the cap is what stops the forcing from
-- diverging.
forkRenderLine :: String -> String
forkRenderLine ~s =
    let t = forkTakeCapped forkLineCharCap (forkAsciiOnly s)
     in length t `seq` t

-- | Emitted in place of a line whose renderer raised.  Silence would be safe
-- but useless: in a debugging build, "this trace point fired and its renderer
-- is broken" is itself the diagnosis.
forkRenderFailedPrefix :: String
forkRenderFailedPrefix = "[TLS-DBG] <trace line dropped: renderer failed: "

----------------------------------------------------------------
-- (fork) Bounded physical writes
----------------------------------------------------------------

-- | Largest number of characters handed to a single 'ForkLogIO.putStrLn'.
--
-- This is not a cosmetic limit; it is what keeps the logger cancellable.
--
-- In a container, stdout is a pipe to the log collector.  @PIPE_BUF@ is 4096
-- bytes on Linux, and the kernel reports a pipe writable only once at least
-- @PIPE_BUF@ bytes are free.  A @write(2)@ of no more than @PIPE_BUF@ bytes
-- therefore never blocks once @poll@ says the fd is ready: GHC does the waiting
-- in 'GHC.Conc.threadWaitWrite', which is an ordinary interruptible operation.
--
-- A larger write behaves completely differently.  On Linux a blocking write of
-- @n > PIPE_BUF@ bytes to a pipe does not return until all @n@ bytes have been
-- transferred, so it blocks /inside/ the @safe@ foreign call to @write(2)@ that
-- GHC's threaded RTS uses for the (blocking) standard handles -- and a thread
-- inside a safe foreign call cannot be delivered an asynchronous exception.
-- Neither @System.Timeout.timeout@ nor 'ForkLogC.killThread' can rescue it.
-- If the log collector ever stops draining, one oversized trace line wedges the
-- emitting request thread permanently, still holding whatever TLS lock it was
-- under, and every other thread that traces then queues behind it on the stdout
-- handle: the process stops serving and only a restart recovers it.
--
-- The package emits lines far past that threshold by design (a
-- @Certificate13@ packet dump is capped at 65536 characters in
-- "Network.TLS.Hooks", 'forkLineCharCap' allows 262144), so long lines are
-- split into several physical writes instead.  4000 leaves room for the
-- newline and for 'forkContPrefix' within @PIPE_BUF@.
--
-- 'forkAsciiOnly' has already reduced the line to printable ASCII, so one
-- character is exactly one byte here whatever encoding stdout carries.
forkWriteChunkChars :: Int
forkWriteChunkChars = 4000

-- | Marks the continuation of a line that had to be split across several
-- physical writes.  Keeping the @[TLS-DBG]@ prefix means a continuation is
-- still picked up by a grep for the tag; reassembly is concatenation after
-- dropping this prefix.
forkContPrefix :: String
forkContPrefix = "[TLS-DBG] (cont) "

-- | Split a fully rendered, ASCII-only line into physical writes that each stay
-- within @PIPE_BUF@.  Total and terminating: the chunk size is at least 1 and
-- the input has already been capped and forced by 'forkRenderLine'.
forkSplitForWrite :: String -> [String]
forkSplitForWrite s0 = case splitAt forkWriteChunkChars s0 of
    (hd, []) -> [hd]
    (hd, tl) -> hd : goCont tl
  where
    contChunk = max 1 (forkWriteChunkChars - length forkContPrefix)
    goCont [] = []
    goCont s = case splitAt contChunk s of
        (hd, []) -> [forkContPrefix ++ hd]
        (hd, tl) -> (forkContPrefix ++ hd) : goCont tl

-- | Serializes the chunks of one logical trace line.
--
-- Without it the continuations of two concurrent lines interleave.  (GHC
-- already releases the stdout handle lock between the internal buffer commits
-- of one long 'ForkLogIO.putStrLn', so long lines interleave today; this makes
-- them contiguous.)
--
-- It cannot deadlock against the instrumented code: it is private to this
-- module, no code outside 'forkSafeEmitLine' can take it, nothing but the
-- stdout writes runs while it is held, it is never acquired reentrantly, and
-- 'ForkLogC.withMVar' releases it on any exception including an asynchronous
-- one.  A thread waiting here would otherwise be waiting on the stdout handle's
-- own lock.
forkWriteLock :: ForkLogC.MVar ()
forkWriteLock = unsafePerformIO (ForkLogC.newMVar ())
{-# NOINLINE forkWriteLock #-}

-- | Write one already-prefixed line to stdout.  Never throws synchronously;
-- re-throws asynchronous exceptions unchanged.
--
-- 'ForkLogIO.putStrLn', deliberately not 'print': 'print' on a 'String' goes
-- through 'show', which wraps the line in quotes and backslash-escapes every
-- internal quote and backslash.  That mangles exactly the payloads this trace
-- exists for -- distinguished names (@CN=...,O=...@) and hex blobs -- and makes
-- the log unusable for a byte-for-byte comparison.
--
-- Rendering and writing are separated deliberately.  The rendering is forced by
-- 'ForkLogE.evaluate' inside its own handler, so a bottom or a runaway renderer
-- cannot escape /and/ cannot produce a half-written line: nothing is written
-- until the whole line exists.  A failed render then falls back to a fixed,
-- pure-ASCII marker carrying the failure, which is itself rendered through the
-- same guarded path before it is trusted.
--
-- The write itself is chunked ('forkSplitForWrite'): see 'forkWriteChunkChars'
-- for why a single oversized 'ForkLogIO.putStrLn' is the one thing in this
-- module that can hang a request thread beyond the reach of @timeout@.
forkSafeEmitLine :: String -> IO ()
forkSafeEmitLine ~s = do
    r <- ForkLogE.try (ForkLogE.evaluate (forkRenderLine s))
    case (r :: Either ForkLogE.SomeException String) of
        Right t -> emitRaw t
        Left e
            | forkIsAsyncException e -> ForkLogE.throwIO e
            | otherwise -> emitRenderFailure e
  where
    emitRaw t =
        forkSwallowSync $
            ForkLogC.withMVar forkWriteLock $ \_ ->
                mapM_ putChunk (forkSplitForWrite t)
    -- The 'hFlush' per chunk is what keeps the handle's own buffer from
    -- coalescing two chunks into one oversized write(2).
    putChunk c = ForkLogIO.putStrLn c >> ForkLogIO.hFlush ForkLogIO.stdout
    emitRenderFailure e = do
        r2 <-
            ForkLogE.try
                (ForkLogE.evaluate (forkRenderLine (forkRenderFailedPrefix ++ show e ++ ">")))
        case (r2 :: Either ForkLogE.SomeException String) of
            Right t2 -> emitRaw t2
            Left e2
                | forkIsAsyncException e2 -> ForkLogE.throwIO e2
                -- 'show' on the exception was itself bottom.  This literal is
                -- printable ASCII, so it cannot fail to render or to encode.
                | otherwise -> emitRaw (forkRenderFailedPrefix ++ "unshowable>")

----------------------------------------------------------------
-- (fork) Build provenance
----------------------------------------------------------------

-- | Set once the build-provenance banner has been emitted.
--
-- 'unsafePerformIO' + NOINLINE is the standard top-level-mutable-variable
-- idiom; the NOINLINE is what makes it /one/ ref for the whole process rather
-- than one per use site.
tlsDebugBannerRef :: IORef Bool
tlsDebugBannerRef = unsafePerformIO (newIORef False)
{-# NOINLINE tlsDebugBannerRef #-}

-- | The provenance line.  Names the package, its version and the fact that this
-- is the instrumented fork, so a log can prove which @tls@ is linked in.
tlsDebugBannerLine :: String
tlsDebugBannerLine =
    "[TLS-DBG] BUILD-PROVENANCE: package=tls version=2.1.8.2 build=INSTRUMENTED-FORK"
        ++ " branch=tls-check alwaysOn=True module=Network.TLS.DebugLog"

-- | Print, at most once per process, proof that this instrumented fork is the
-- code actually linked into the running binary.
--
-- Without it a silently-unapplied source override means the whole exercise
-- traces some other build of @tls@ and nobody notices.
--
-- The one-shot cell is an 'atomicModifyIORef'', not a lock: concurrent first
-- calls are resolved by a CAS, exactly one of them sees 'True', and no thread
-- can ever block on another here.  It is also the /only/ mutable state the
-- logger owns, so the logger cannot deadlock against the code it instruments.
tlsDebugBanner :: IO ()
tlsDebugBanner = do
    firstTime <- atomicModifyIORef' tlsDebugBannerRef (\done -> (True, not done))
    when firstTime $ forkSafeEmitLine tlsDebugBannerLine
{-# NOINLINE tlsDebugBanner #-}

----------------------------------------------------------------
-- (fork) Entry points
----------------------------------------------------------------

-- | Emit a trace line.  Never throws synchronously; re-throws asynchronous
-- exceptions unchanged.
--
-- Every line carries a monotonic nanosecond timestamp and the emitting
-- 'Control.Concurrent.ThreadId' before the message, so lines can be correlated
-- with the other instrumented packages' output (see the module header).
tlsDebug :: String -> IO ()
tlsDebug ~msg = tlsDebugSafeIO $ do
    tlsDebugBanner
    t <- ForkLogClock.getMonotonicTimeNSec
    tid <- ForkLogC.myThreadId
    forkSafeEmitLine
        ( "[TLS-DBG] t="
            ++ show t
            ++ " tid="
            ++ show tid
            ++ " "
            ++ msg
        )

-- | Emit a high-volume trace line, gated on 'tlsDebugVerbose'.
tlsDebugV :: String -> IO ()
tlsDebugV ~msg = when tlsDebugVerbose $ tlsDebug msg

-- | Host-aware variant: prefixes the line with the SNI host.
--
-- 'tlsDebugHostFilter' is applied inside 'tlsDebugSafeIO' rather than outside,
-- so that even a bottom reaching the filter cannot escape into the handshake.
tlsDebugHost :: String -> String -> IO ()
tlsDebugHost ~host ~msg =
    tlsDebugSafeIO $
        when (tlsDebugHostFilter host) $
            tlsDebug ("host=" ++ show host ++ " " ++ msg)

----------------------------------------------------------------
-- (fork) Rendering helpers
----------------------------------------------------------------

-- | Largest number of bytes 'hexOf' will convert.
--
-- Unlike the string renderers, the base16 conversion is not lazy -- it builds a
-- whole strict 'ByteString' -- so the cap has to be applied to the /input/,
-- before the conversion, rather than left to 'forkLineCharCap'.  Every present
-- caller passes at most a few kilobytes (a certificate, a signature, a public
-- key, a ClientHello); the cap only exists so that a future caller handed a
-- multi-megabyte buffer cannot spike the heap.
hexOfByteCap :: Int
hexOfByteCap = 65536

-- | Lower-case hex of a 'ByteString', with no quotes and no @0x@ prefix, so
-- the value can be pasted straight into @xxd -r -p@ or an @openssl@ pipeline.
-- Truncation, if it happens, is stated explicitly so a truncated blob is never
-- mistaken for a complete one.
hexOf :: ByteString -> String
hexOf ~bs =
    let n = C8.length bs
        shown = C8.unpack (convertToBase Base16 (C8.take hexOfByteCap bs) :: ByteString)
     in if n > hexOfByteCap
            then shown ++ "...<truncated, " ++ show n ++ " bytes total>"
            else shown
