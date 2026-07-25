-- | Lightweight wire/handshake tracing used to diagnose connection failures
-- (e.g. a peer that closes right after the handshake with no application data,
-- surfacing to http-client as @NoResponseDataReceived@).
--
-- All output is a single stdout line prefixed with @[TLS-DBG]@.
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
) where

import Control.Exception (SomeException, try)
import Control.Monad (when)
import System.IO (hFlush, stdout)

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

-- | Emit a trace line. Never throws.
tlsDebug :: String -> IO ()
tlsDebug msg =
    when tlsDebugEnabled $ do
        _ <-
            try (print ("[TLS-DBG] " ++ msg) >> hFlush stdout)
                :: IO (Either SomeException ())
        pure ()

-- | Host-aware variant: prefixes the line with the SNI host.
tlsDebugHost :: String -> String -> IO ()
tlsDebugHost host msg =
    when (tlsDebugHostFilter host) $ tlsDebug ("host=" ++ show host ++ " " ++ msg)
