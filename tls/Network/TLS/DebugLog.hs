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
module Network.TLS.DebugLog (
    tlsDebugEnabled,
    tlsDebug,
    tlsDebugVerbose,
    tlsDebugV,
    tlsDebugHost,
    tlsDebugHostFilter,
    hexOf,
) where

import Control.Concurrent (myThreadId)
import Control.Exception (SomeException, try)
import Control.Monad (when)
import Data.ByteArray.Encoding (Base (Base16), convertToBase)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as C8
import Data.IORef (IORef, atomicModifyIORef', newIORef)
import GHC.Clock (getMonotonicTimeNSec)
import System.IO (hFlush, stdout)
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

-- | Emit a high-volume trace line, gated on 'tlsDebugVerbose'.
tlsDebugV :: String -> IO ()
tlsDebugV msg = when tlsDebugVerbose $ tlsDebug msg

-- | Set once the build-provenance banner has been emitted.
--
-- 'unsafePerformIO' + NOINLINE is the standard top-level-mutable-variable
-- idiom; the NOINLINE is what makes it /one/ ref for the whole process rather
-- than one per use site.
tlsDebugBannerRef :: IORef Bool
tlsDebugBannerRef = unsafePerformIO (newIORef False)
{-# NOINLINE tlsDebugBannerRef #-}

-- | Print, at most once per process, proof that this instrumented fork is the
-- code actually linked into the running binary.
--
-- Without it a silently-unapplied source override means the whole exercise
-- traces some other build of @tls@ and nobody notices.  The 'atomicModifyIORef''
-- makes the one-shot race-free, and the whole call is made from inside
-- 'tlsDebug'\'s exception guard, so it cannot throw into a caller.
tlsDebugBanner :: IO ()
tlsDebugBanner = do
    firstTime <- atomicModifyIORef' tlsDebugBannerRef (\done -> (True, not done))
    when firstTime $ do
        putStrLn
            "[TLS-DBG] BUILD-PROVENANCE: tls-2.1.8.2 INSTRUMENTED FORK (branch tls-check)"
        hFlush stdout
{-# NOINLINE tlsDebugBanner #-}

-- | Emit a trace line. Never throws.
--
-- Every line carries a monotonic nanosecond timestamp and the emitting
-- 'Control.Concurrent.ThreadId' before the message, so lines can be correlated
-- with the other instrumented packages' output (see the module header).
--
-- 'putStrLn', deliberately not 'print': 'print' on a 'String' goes through
-- 'show', which wraps the line in quotes and backslash-escapes every internal
-- quote and backslash.  That mangles exactly the payloads this trace exists
-- for -- distinguished names (@CN=...,O=...@ rendered by 'show') and hex blobs
-- -- and makes the log unusable for a byte-for-byte comparison.
tlsDebug :: String -> IO ()
tlsDebug msg =
    when tlsDebugEnabled $ do
        _ <- try emit :: IO (Either SomeException ())
        pure ()
  where
    emit = do
        tlsDebugBanner
        t <- getMonotonicTimeNSec
        tid <- myThreadId
        putStrLn
            ( "[TLS-DBG] t="
                ++ show t
                ++ " tid="
                ++ show tid
                ++ " "
                ++ msg
            )
        hFlush stdout

-- | Lower-case hex of a 'ByteString', with no quotes and no @0x@ prefix, so
-- the value can be pasted straight into @xxd -r -p@ or an @openssl@ pipeline.
hexOf :: ByteString -> String
hexOf bs = C8.unpack (convertToBase Base16 bs :: ByteString)

-- | Host-aware variant: prefixes the line with the SNI host.
tlsDebugHost :: String -> String -> IO ()
tlsDebugHost host msg =
    when (tlsDebugHostFilter host) $ tlsDebug ("host=" ++ show host ++ " " ++ msg)
