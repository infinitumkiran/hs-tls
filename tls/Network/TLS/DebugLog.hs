-- | Lightweight, env-var-gated wire/handshake tracing used to diagnose
-- connection failures (e.g. a peer that closes right after the handshake with
-- no application data, surfacing to http-client as @NoResponseDataReceived@).
--
-- All output is a single stdout line prefixed with @[TLS-DBG]@ and is emitted
-- ONLY when the environment variable @TLS_DEBUG@ is set to a truthy value
-- (@1@/@true@/@yes@/@on@). When unset there is zero overhead beyond a memoized
-- Bool read, so this is safe to leave compiled into the library.
--
-- Optionally, @TLS_DEBUG_HOST@ restricts host-aware call sites to connections
-- whose SNI contains that substring (e.g. @netcetera@), keeping the trace quiet
-- in a process that opens many unrelated TLS connections.
module Network.TLS.DebugLog (
    tlsDebugEnabled,
    tlsDebug,
    tlsDebugHost,
    tlsDebugHostFilter,
) where

import Control.Exception (SomeException, try)
import Control.Monad (when)
import Data.List (isInfixOf)
import System.Environment (lookupEnv)
import System.IO (hFlush, stdout)
import System.IO.Unsafe (unsafePerformIO)

-- | Whether @TLS_DEBUG@ enables tracing. Read once and memoized.
{-# NOINLINE tlsDebugEnabled #-}
tlsDebugEnabled :: Bool
tlsDebugEnabled = unsafePerformIO $ do
    mv <- lookupEnv "TLS_DEBUG"
    pure $ case mv of
        Just v -> v `elem` ["1", "true", "TRUE", "yes", "on", "ON"]
        Nothing -> False

-- | Optional SNI substring filter from @TLS_DEBUG_HOST@ (memoized).
{-# NOINLINE tlsDebugHostSubstr #-}
tlsDebugHostSubstr :: Maybe String
tlsDebugHostSubstr = unsafePerformIO $ lookupEnv "TLS_DEBUG_HOST"

-- | True if the given SNI/host should be traced under the current filter.
-- With no @TLS_DEBUG_HOST@ set, every host passes.
tlsDebugHostFilter :: String -> Bool
tlsDebugHostFilter host = case tlsDebugHostSubstr of
    Nothing -> True
    Just "" -> True
    Just sub -> sub `isInfixOf` host

-- | Emit a trace line (no-op unless @TLS_DEBUG@ is truthy). Never throws.
tlsDebug :: String -> IO ()
tlsDebug msg =
    when tlsDebugEnabled $ do
        _ <-
            try (print ("[TLS-DBG] " ++ msg) >> hFlush stdout)
                :: IO (Either SomeException ())
        pure ()

-- | Host-aware variant: only traces when the host passes 'tlsDebugHostFilter'.
tlsDebugHost :: String -> String -> IO ()
tlsDebugHost host msg =
    when (tlsDebugHostFilter host) $ tlsDebug ("host=" ++ show host ++ " " ++ msg)
