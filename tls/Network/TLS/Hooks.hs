module Network.TLS.Hooks (
    Logging (..),
    defaultLogging,
    Hooks (..),
    defaultHooks,
) where

import qualified Data.ByteString as B
import Data.Char (isSpace)
import Data.Default (Default (def))
import Data.List (isInfixOf, isPrefixOf)
import Network.TLS.DebugLog (tlsDebug, tlsDebugV)
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
--
-- @splitAt@ walks at most @n@ elements of @s@ before 'null' answers, so this is
-- bounded even when handed an unbounded rendering.
truncateTrace :: Int -> String -> String
truncateTrace n ~s =
    let (hd, tl) = splitAt n s
     in if null tl then hd else hd ++ "...<truncated>"

-- | (fork) The handshake messages that carry the client-auth flight:
-- @Certificate13@, @CompressedCertificate13@, @CertRequest13@ and
-- @CertVerify13@ (the first pattern matches both certificate messages).  A 1500
-- character cap decapitates precisely these -- a single certificate alone shows
-- as more than 1500 characters -- and the truncated tail is where the
-- interesting part lives (the chain beyond the leaf, the signature bytes, the
-- @certificate_authorities@ list).  They are given a much larger budget; every
-- other packet keeps the small default so the firehose stays readable.
largeTraceMessages :: [String]
largeTraceMessages =
    [ "Certificate13" -- also matches CompressedCertificate13
    , "CertRequest13"
    , "CertVerify13"
    ]

-- | (fork) Cap for one trace line.  The constructor may be nested inside a
-- packet ("Handshake13 [CertVerify13 ..."), so look for it in the head of the
-- string rather than at position 0; 64 characters is well past any wrapper.
traceCap :: String -> Int
traceCap ~s
    | any (`isInfixOf` take 64 s) largeTraceMessages = 65536
    | otherwise = 1500

-- | (fork) Longest constructor name 'sanitizePacket' will echo for a redacted
-- @AppData@ packet.  @takeWhile (not . isSpace)@ is only bounded if the payload
-- rendering happens to contain a space, which is a property of a 'Show'
-- instance rather than a guarantee; the cap makes it one.
appDataTagCap :: Int
appDataTagCap = 32

-- | (fork) Redact application data before tracing.  This library is deployed in
-- a payments path, so @AppData@ packets carry cardholder data and request
-- bodies: only the constructor name is ever emitted, never the payload.  That
-- redaction is unconditional and must stay that way.
-- Handshake packets are safe to show and are merely truncated.
sanitizePacket :: String -> String
sanitizePacket ~s
    | "AppData" `isPrefixOf` s =
        take appDataTagCap (takeWhile (not . isSpace) s) ++ " <payload redacted>"
    | otherwise = truncateTrace (traceCap s) s

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
        { loggingPacketSent = \(~s) -> tlsDebugV ("packet sent: " ++ sanitizePacket s)
        , loggingPacketRecv = \(~s) -> tlsDebugV ("packet recv: " ++ sanitizePacket s)
        , loggingIOSent = \(~bs) -> tlsDebugV ("io sent: " ++ show (B.length bs) ++ " bytes")
        , loggingIORecv = \(~hdr) (~bs) ->
            tlsDebugV
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

-- | The @~@ lazy patterns here are load-bearing for the same reason as in
-- 'defaultLogging': upstream these hooks are @return@ \/ @return . const ()@,
-- which force nothing.  Under @Strict@ a plain @\\hs -> ...@ would force the
-- handshake message and the certificate chain to WHNF at a point where upstream
-- does not, i.e. the instrumentation would have changed evaluation order.
defaultHooks :: Hooks
defaultHooks =
    Hooks
        { hookRecvHandshake = \(~hs) -> traceHandshake "recv handshake12" (show hs) >> return hs
        , hookRecvHandshake13 = \(~hs) -> traceHandshake "recv handshake13" (show hs) >> return hs
        , hookRecvCertificates = \(~cc) ->
            tlsDebug ("peer certificate chain received: " ++ describeCertChain cc)
        , hookLogging = def
        }
  where
    traceHandshake tag (~s) = tlsDebugV (tag ++ ": " ++ sanitizePacket s)

instance Default Hooks where
    def = defaultHooks
