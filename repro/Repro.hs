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
import Network.Socket
import System.Environment (getArgs)
import System.IO (BufferMode (LineBuffering), hSetBuffering, stdout)

import Network.TLS
import Network.TLS.Extra.Cipher (ciphersuite_default)

main :: IO ()
main = do
    hSetBuffering stdout LineBuffering
    (host, port, ver) <- parseArgs <$> getArgs
    putStrLn $ "== tls-repro " ++ host ++ ":" ++ port ++ " forcing " ++ show ver ++ " =="
    bracket (connectTo host port) close $ \sock -> do
        ctx <- contextNew sock (mkParams host ver)
        handshake ctx
        minfo <- contextGetInformation ctx
        putStrLn $ "handshake OK; negotiated " ++ maybe "?" (show . infoVersion) minfo
        let req =
                "GET / HTTP/1.1\r\nHost: " <> BC.pack host
                    <> "\r\nConnection: close\r\nUser-Agent: tls-repro\r\n\r\n"
        sendData ctx (L.fromStrict req)
        n <- drainResponse ctx 0
        putStrLn $
            "drained response (~" ++ show n ++ " bytes); recvData returned \"\" (server closed)"
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

drainResponse :: Context -> Int -> IO Int
drainResponse ctx !n = do
    b <- recvData ctx
    if B.null b then pure n else drainResponse ctx (n + B.length b)

connectTo :: HostName -> ServiceName -> IO Socket
connectTo host port = do
    ai : _ <-
        getAddrInfo (Just defaultHints{addrSocketType = Stream}) (Just host) (Just port)
    sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
    connect sock (addrAddress ai)
    pure sock

mkParams :: HostName -> Version -> ClientParams
mkParams host ver =
    let base = defaultParamsClient host BC.empty
     in base
            { clientSupported =
                (clientSupported base)
                    { supportedVersions = [ver]
                    , supportedCiphers = ciphersuite_default
                    }
            , -- repro only: accept any certificate so we need no system cert store
              clientHooks =
                (clientHooks base){onServerCertificate = \_ _ _ _ -> pure []}
            }

parseArgs :: [String] -> (HostName, ServiceName, Version)
parseArgs (h : p : v : _) = (h, p, readVer v)
parseArgs (h : p : _) = (h, p, TLS13)
parseArgs (h : _) = (h, "443", TLS13)
parseArgs _ = ("www.google.com", "443", TLS13)

readVer :: String -> Version
readVer "1.2" = TLS12
readVer "1.1" = TLS11
readVer "1.0" = TLS10
readVer _ = TLS13
