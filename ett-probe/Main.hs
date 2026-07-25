{-# LANGUAGE ScopedTypeVariables #-}

-- | Minimal outbound-HTTPS probe that runs through the instrumented forks.
--
-- > EULER_TLS_TRACE=all ett-probe https://juspay.3ds-server.prev.netcetera-cloud-payment.ch/3ds/authentication
--
-- Environment:
--
-- * @EULER_TLS_TRACE@       - see Debug.EulerTrace.*; @all@ or a package list
-- * @EULER_TLS_TRACE_FILE@  - write the trace here instead of stderr
-- * @ETT_PROBE_TLS12=1@     - offer TLS 1.2 only (option A from TLS_2x_MIGRATION.md)
-- * @ETT_PROBE_METHOD@      - request method, default GET
module Main (main) where

import qualified Control.Exception as E
import qualified Data.ByteString.Lazy.Char8 as L8
import Data.Default.Class (def)
import Network.HTTP.Client
import Network.Connection (TLSSettings (..))
import Network.HTTP.Client.TLS (mkManagerSettings, newTlsManagerWith,
                                tlsManagerSettings)
import Network.TLS (Supported (..), Version (TLS12))
import System.Environment (getArgs, lookupEnv)
import System.Exit (exitFailure)
import GHC.IO.Handle (hDuplicateTo)
import System.IO (BufferMode (LineBuffering), IOMode (AppendMode), hPutStrLn,
                  hSetBuffering, stderr, withFile)

main :: IO ()
main = do
    -- The tracer only ever writes to stderr (see Debug.EulerTrace.*), so honour
    -- EULER_TLS_TRACE_FILE here by pointing this process's stderr at it.
    mfile <- lookupEnv "EULER_TLS_TRACE_FILE"
    case mfile of
        Nothing -> probe
        Just p -> withFile p AppendMode $ \h -> do
            hSetBuffering h LineBuffering
            hDuplicateTo h stderr
            probe

probe :: IO ()
probe = do
    args <- getArgs
    url <- case args of
        (u : _) -> return u
        [] -> do
            hPutStrLn stderr "usage: ett-probe <url>"
            exitFailure
    tls12 <- fmap (== Just "1") (lookupEnv "ETT_PROBE_TLS12")
    method' <- fmap (maybe "GET" id) (lookupEnv "ETT_PROBE_METHOD")

    let settings
          | tls12 = mkManagerSettings
                        def {settingClientSupported = def {supportedVersions = [TLS12]}}
                        Nothing
          | otherwise = tlsManagerSettings
    mgr <- newTlsManagerWith settings
    req0 <- parseRequest url
    let req = req0 {method = L8.toStrict (L8.pack method')}

    hPutStrLn stderr ("== probing " ++ url ++ (if tls12 then " (TLS1.2 only)" else ""))
    r <- E.try (httpLbs req mgr)
    case r of
        Right resp -> do
            hPutStrLn stderr ("== OK " ++ show (responseStatus resp)
                              ++ " body=" ++ show (L8.length (responseBody resp)) ++ "B")
        Left (e :: E.SomeException) -> do
            hPutStrLn stderr ("== FAILED " ++ show e)
            exitFailure
