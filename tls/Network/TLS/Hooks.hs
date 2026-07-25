module Network.TLS.Hooks (
    Logging (..),
    defaultLogging,
    Hooks (..),
    defaultHooks,
) where

import qualified Data.ByteString as B
import Data.Char (isSpace)
import Data.Default (Default (def))
import Data.List (isPrefixOf)
import Network.TLS.DebugLog (tlsDebug)
import Network.TLS.Struct (Handshake, Header)
import Network.TLS.Struct13 (Handshake13)
import Network.TLS.X509 (CertificateChain, describeCertChain)

-- | Hooks for logging
--
-- This is called when sending and receiving packets and IO
data Logging = Logging
    { loggingPacketSent :: String -> IO ()
    , loggingPacketRecv :: String -> IO ()
    , loggingIOSent :: B.ByteString -> IO ()
    , loggingIORecv :: Header -> B.ByteString -> IO ()
    }

-- | (fork) Cap a trace line so one large message cannot flood the log.
truncateTrace :: Int -> String -> String
truncateTrace n s =
    let (hd, tl) = splitAt n s
     in if null tl then hd else hd ++ "...<truncated>"

-- | (fork) Redact application data before tracing.  This library is deployed in
-- a payments path, so @AppData@ packets carry cardholder data and request
-- bodies: only the constructor name is ever emitted, never the payload.
-- Handshake packets are safe to show and are merely truncated.
sanitizePacket :: String -> String
sanitizePacket s
    | "AppData" `isPrefixOf` s = takeWhile (not . isSpace) s ++ " <payload redacted>"
    | otherwise = truncateTrace 1500 s

-- | (fork) Trace every packet and record-layer read\/write when @TLS_DEBUG@ is
-- set.  Wiring this into 'defaultLogging' (rather than requiring callers to
-- install their own 'Logging') means any client using 'defaultParamsClient'
-- gets a full wire trace with no code change -- including callers that override
-- other 'Hooks' fields via record update, since those keep this default.
--
-- The @~@ lazy patterns are load-bearing: this module is compiled with
-- @Strict@, which would otherwise force the @show pkt@ thunk built at every
-- call site even when tracing is disabled.
defaultLogging :: Logging
defaultLogging =
    Logging
        { loggingPacketSent = \(~s) -> tlsDebug ("packet sent: " ++ sanitizePacket s)
        , loggingPacketRecv = \(~s) -> tlsDebug ("packet recv: " ++ sanitizePacket s)
        , loggingIOSent = \(~bs) -> tlsDebug ("io sent: " ++ show (B.length bs) ++ " bytes")
        , loggingIORecv = \(~hdr) (~bs) ->
            tlsDebug
                ( "io recv: header="
                    ++ show hdr
                    ++ " payload="
                    ++ show (B.length bs)
                    ++ " bytes"
                )
        }

instance Default Logging where
    def = defaultLogging

-- | A collection of hooks actions.
data Hooks = Hooks
    { hookRecvHandshake :: Handshake -> IO Handshake
    -- ^ called at each handshake message received
    , hookRecvHandshake13 :: Handshake13 -> IO Handshake13
    -- ^ called at each handshake message received for TLS 1.3
    , hookRecvCertificates :: CertificateChain -> IO ()
    -- ^ called at each certificate chain message received
    , hookLogging :: Logging
    -- ^ hooks on IO and packets, receiving and sending.
    }

defaultHooks :: Hooks
defaultHooks =
    Hooks
        { hookRecvHandshake = \hs -> traceHandshake "recv handshake12" (show hs) >> return hs
        , hookRecvHandshake13 = \hs -> traceHandshake "recv handshake13" (show hs) >> return hs
        , hookRecvCertificates = \cc ->
            tlsDebug ("peer certificate chain received: " ++ describeCertChain cc)
        , hookLogging = def
        }
  where
    traceHandshake tag (~s) = tlsDebug (tag ++ ": " ++ sanitizePacket s)

instance Default Hooks where
    def = defaultHooks
