{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Reproduces the 3DS "HTTP 500 / InternalException end of file" against a
-- live online TLS 1.3 endpoint, at the TLS layer.
--
-- It drives the exact sequence http-client + crypton-connection perform:
--   1. handshake, send an HTTP request with `Connection: close`
--   2. read the response with recvData until it returns "" (server closed)
--   3. do ONE MORE recvData on the now-closed context
--
-- crypton-connection's connectionGetChunkBase does step 3 on every body read:
--   chunk <- TLS.recvData ctx;  if B.null chunk then <clean EOF> else ...
-- So whether recvData RETURNS "" or THROWS on that extra read is precisely the
-- difference between HTTP 200 and HTTP 500 (InternalException).
--
-- Usage:  tls-repro [HOST [PORT [1.3|1.2|1.1|1.0]]]
module Main (main) where

import Control.Exception (SomeException (..), bracket, try)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy as L
import Data.Maybe (isJust)
import Network.Socket
import System.Environment (getArgs, lookupEnv)
import System.IO (BufferMode (LineBuffering), hSetBuffering, stdout)

import Network.TLS
import Network.TLS.Extra.Cipher (ciphersuite_default, ciphersuite_legacyDefault)

main :: IO ()
main = do
    hSetBuffering stdout LineBuffering
    (host, port, vers) <- parseArgs <$> getArgs
    legacy <- (== Just "1") <$> lookupEnv "REPRO_LEGACY"
    eulerMode <- (== Just "1") <$> lookupEnv "REPRO_EULER"
    mcred <- loadClientCred
    putStrLn $
        "== tls-repro " ++ host ++ ":" ++ port ++ " offering " ++ show vers
            ++ (if legacy then " [legacy fingerprint]" else "")
            ++ (if eulerMode then " [euler-exact]" else "")
            ++ (if isJust mcred then " [client cert]" else "") ++ " =="
    bracket (connectTo host port) close $ \sock -> do
        let params =
                if eulerMode
                    then eulerParams host mcred
                    else mkParams host vers legacy mcred
        ctx <- contextNew sock params
        handshake ctx
        minfo <- contextGetInformation ctx
        putStrLn $ "handshake OK; negotiated " ++ maybe "?" (show . infoVersion) minfo
        path <- maybe "/" id <$> lookupEnv "REPRO_PATH"
        let req =
                "GET " <> BC.pack path <> " HTTP/1.1\r\nHost: " <> BC.pack host
                    <> "\r\nConnection: close\r\nUser-Agent: tls-repro\r\n\r\n"
        sendData ctx (L.fromStrict req)
        body <- drainResponse ctx B.empty
        putStrLn $
            "drained response (" ++ show (B.length body) ++ " bytes); recvData returned \"\" (server closed)"
        BC.putStrLn body
        putStrLn "-- extra read on the closed context (what crypton-connection does) --"
        r <- try (recvData ctx)
        case r of
            Right b
                | B.null b ->
                    putStrLn "RESULT: recvData => \"\"   graceful EOF  =>  http-client HTTP 200   [FIXED]"
                | otherwise ->
                    putStrLn $ "RESULT: recvData => " ++ show (B.length b) ++ " bytes (unexpected)"
            Left (e :: SomeException) ->
                putStrLn $
                    "RESULT: recvData THREW: " ++ show e
                        ++ "  =>  http-client InternalException => HTTP 500   [BROKEN]"

drainResponse :: Context -> B.ByteString -> IO B.ByteString
drainResponse ctx !acc = do
    b <- recvData ctx
    if B.null b then pure acc else drainResponse ctx (acc <> b)

connectTo :: HostName -> ServiceName -> IO Socket
connectTo host port = do
    ai : _ <-
        getAddrInfo (Just defaultHints{addrSocketType = Stream}) (Just host) (Just port)
    sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
    connect sock (addrAddress ai)
    pure sock

-- | Load a client certificate + key (PEM) from $REPRO_CERT / $REPRO_KEY, to send
-- the same mTLS credential euler presents to netcetera.  Absent => no client cert.
loadClientCred :: IO (Maybe Credential)
loadClientCred = do
    mc <- lookupEnv "REPRO_CERT"
    mk <- lookupEnv "REPRO_KEY"
    case (mc, mk) of
        (Just c, Just k) -> do
            r <- credentialLoadX509 c k
            case r of
                Right cred -> do
                    putStrLn $ "loaded client cert " ++ c ++ " (key " ++ k ++ ")"
                    pure (Just cred)
                Left e -> do
                    putStrLn $ "WARNING: client cert load failed: " ++ e
                    pure Nothing
        _ -> pure Nothing

-- | EXACTLY what euler-hs mkClientParams does: take defaultParamsClient (whose
-- clientSupported = def) and override only supportedCiphers + AllowEMS.  With the
-- fork's `def = defaultSupportedBackwardCompat`, this shows the real ClientHello
-- euler now emits (no euler-hs change).
eulerParams :: HostName -> Maybe Credential -> ClientParams
eulerParams host mcred =
    let base = defaultParamsClient host BC.empty
     in base
            { clientSupported =
                (clientSupported base)
                    { supportedCiphers = ciphersuite_default
                    , supportedExtendedMainSecret = AllowEMS
                    }
            , clientHooks =
                (clientHooks base)
                    { onServerCertificate = \_ _ _ _ -> pure []
                    , onSuggestALPN = pure (Just ["http/1.1"])
                    , onCertificateRequest = \_ -> pure mcred
                    }
            }

mkParams :: HostName -> [Version] -> Bool -> Maybe Credential -> ClientParams
mkParams host vers legacy mcred =
    let base = defaultParamsClient host BC.empty
     in base
            { clientSupported =
                (clientSupported base)
                    { supportedVersions = vers
                    , supportedCiphers =
                        if legacy then ciphersuite_legacyDefault else ciphersuite_default
                    , supportedGroups =
                        if legacy
                            then legacyClientHelloGroups
                            else supportedGroups (clientSupported base)
                    , -- emit the tls-1.6.0-shaped ClientHello when in legacy mode
                      supportedLegacyClientHello = legacy
                    , -- match euler-hs mkClientParams
                      supportedExtendedMainSecret = AllowEMS
                    }
            , clientHooks =
                (clientHooks base)
                    { -- repro only: accept any certificate (no system cert store)
                      onServerCertificate = \_ _ _ _ -> pure []
                    , -- http-client advertises ALPN; a fingerprinting WAF may
                      -- reset a ClientHello without it
                      onSuggestALPN = pure (Just ["http/1.1"])
                    , -- present euler's netcetera mTLS cert when provided
                      onCertificateRequest = \_ -> pure mcred
                    }
            }

parseArgs :: [String] -> (HostName, ServiceName, [Version])
parseArgs (h : p : v : _) = (h, p, readVers v)
parseArgs (h : p : _) = (h, p, [TLS13, TLS12])
parseArgs (h : _) = (h, "443", [TLS13, TLS12])
parseArgs _ = ("www.google.com", "443", [TLS13, TLS12])

readVers :: String -> [Version]
readVers "1.3" = [TLS13]
readVers "1.2" = [TLS12]
readVers "1.1" = [TLS11]
readVers "1.0" = [TLS10]
readVers _ = [TLS13, TLS12]
