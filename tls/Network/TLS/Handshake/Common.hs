{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.TLS.Handshake.Common
    ( handshakeFailed
    , handleException
    , unexpected
    , newSession
    , handshakeTerminate
    -- * sending packets
    , sendChangeCipherAndFinish
    -- * receiving packets
    , recvChangeCipherAndFinish
    , RecvState(..)
    , runRecvState
    , recvPacketHandshake
    , onRecvStateHandshake
    , ensureRecvComplete
    , processExtendedMasterSec
    , extensionLookup
    , getSessionData
    , storePrivInfo
    , isSupportedGroup
    , checkSupportedGroup
    , errorToAlert
    , errorToAlertMessage
    ) where

import qualified Data.ByteString as B
import Control.Concurrent.MVar

import Network.TLS.Parameters
import Network.TLS.Compression
import Network.TLS.Context.Internal
import Network.TLS.Extension
import Network.TLS.Session
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.IO
import Network.TLS.State
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.State
import Network.TLS.Record.State
import Network.TLS.Measurement
import Network.TLS.Types
import Network.TLS.Cipher
import Network.TLS.Crypto
import Network.TLS.Util
import Network.TLS.X509
import Network.TLS.Imports

import Control.Monad.State.Strict
import Control.Exception (IOException, handle, fromException, throwIO)
import Data.IORef (writeIORef)
import qualified Debug.EulerTrace.Tls as ETT__

handshakeFailed :: TLSError -> IO ()
handshakeFailed err = ETT__.tio "Network.TLS.Handshake.Common.handshakeFailed" ETT__.$ throwIO $ HandshakeFailed err

handleException :: Context -> IO () -> IO ()
handleException ctx f = ETT__.tio "Network.TLS.Handshake.Common.handleException" ETT__.$ catchException f $ \exception -> do
    -- If the error was an Uncontextualized TLSException, we replace the
    -- context with HandshakeFailed. If it's anything else, we convert
    -- it to a string and wrap it with Error_Misc and HandshakeFailed.
    let tlserror = case fromException exception of
          Just e | Uncontextualized e' <- e -> e'
          _ -> Error_Misc (show exception)
    setEstablished ctx NotEstablished
    handle ignoreIOErr $ do
        tls13 <- tls13orLater ctx
        if tls13 then
            sendPacket13 ctx $ Alert13 [errorToAlert tlserror]
          else
            sendPacket ctx $ Alert [errorToAlert tlserror]
    handshakeFailed tlserror
  where
    ignoreIOErr :: IOException -> IO ()
    ignoreIOErr _ = return ()

errorToAlert :: TLSError -> (AlertLevel, AlertDescription)
errorToAlert (Error_Protocol _ ad)   = ETT__.t "Network.TLS.Handshake.Common.errorToAlert" ETT__.$ (AlertLevel_Fatal, ad)
errorToAlert (Error_Protocol_Warning _ ad)   = ETT__.t "Network.TLS.Handshake.Common.errorToAlert" ETT__.$ (AlertLevel_Warning, ad)
errorToAlert (Error_Packet_unexpected _ _) = ETT__.t "Network.TLS.Handshake.Common.errorToAlert" ETT__.$ (AlertLevel_Fatal, UnexpectedMessage)
errorToAlert (Error_Packet_Parsing msg)
  | "invalid version" `isInfixOf` msg      = ETT__.t "Network.TLS.Handshake.Common.errorToAlert" ETT__.$ (AlertLevel_Fatal, ProtocolVersion)
  | "request_update"  `isInfixOf` msg      = ETT__.t "Network.TLS.Handshake.Common.errorToAlert" ETT__.$ (AlertLevel_Fatal, IllegalParameter)
  | otherwise                              = ETT__.t "Network.TLS.Handshake.Common.errorToAlert" ETT__.$ (AlertLevel_Fatal, DecodeError)
errorToAlert _                             = ETT__.t "Network.TLS.Handshake.Common.errorToAlert" ETT__.$ (AlertLevel_Fatal, InternalError)

-- | Return the message that a TLS endpoint can add to its local log for the
-- specified library error.
errorToAlertMessage :: TLSError -> String
errorToAlertMessage (Error_Protocol msg _)         = ETT__.t "Network.TLS.Handshake.Common.errorToAlertMessage" ETT__.$ msg
errorToAlertMessage (Error_Protocol_Warning msg _) = ETT__.t "Network.TLS.Handshake.Common.errorToAlertMessage" ETT__.$ msg
errorToAlertMessage (Error_Packet_unexpected msg _)   = ETT__.t "Network.TLS.Handshake.Common.errorToAlertMessage" ETT__.$ msg
errorToAlertMessage (Error_Packet_Parsing msg)        = ETT__.t "Network.TLS.Handshake.Common.errorToAlertMessage" ETT__.$ msg
errorToAlertMessage e                                 = ETT__.t "Network.TLS.Handshake.Common.errorToAlertMessage" ETT__.$ show e

unexpected :: MonadIO m => String -> Maybe String -> m a
unexpected msg expected = ETT__.tm "Network.TLS.Handshake.Common.unexpected" ETT__.$ throwCore $ Error_Packet_unexpected msg (maybe "" (" expected: " ++) expected)

newSession :: Context -> IO Session
newSession ctx
    | supportedSession $ ctxSupported ctx = ETT__.t "Network.TLS.Handshake.Common.newSession" ETT__.$ Session . Just <$> getStateRNG ctx 32
    | otherwise                           = ETT__.t "Network.TLS.Handshake.Common.newSession" ETT__.$ return $ Session Nothing

-- | when a new handshake is done, wrap up & clean up.
handshakeTerminate :: Context -> IO ()
handshakeTerminate ctx = ETT__.tio "Network.TLS.Handshake.Common.handshakeTerminate" ETT__.$ do
    session <- usingState_ ctx getSession
    -- only callback the session established if we have a session
    case session of
        Session (Just sessionId) -> do
            sessionData <- getSessionData ctx
            let !sessionId' = B.copy sessionId
            liftIO $ sessionEstablish (sharedSessionManager $ ctxShared ctx) sessionId' (fromJust "session-data" sessionData)
        _ -> return ()
    -- forget most handshake data and reset bytes counters.
    liftIO $ modifyMVar_ (ctxHandshake ctx) $ \ mhshake ->
        case mhshake of
            Nothing -> return Nothing
            Just hshake ->
                return $ Just (newEmptyHandshake (hstClientVersion hshake) (hstClientRandom hshake))
                    { hstServerRandom = hstServerRandom hshake
                    , hstMasterSecret = hstMasterSecret hshake
                    , hstExtendedMasterSec = hstExtendedMasterSec hshake
                    , hstNegotiatedGroup = hstNegotiatedGroup hshake
                    }
    updateMeasure ctx resetBytesCounters
    -- mark the secure connection up and running.
    setEstablished ctx Established
    return ()

sendChangeCipherAndFinish :: Context
                          -> Role
                          -> IO ()
sendChangeCipherAndFinish ctx role = ETT__.tio "Network.TLS.Handshake.Common.sendChangeCipherAndFinish" ETT__.$ do
    sendPacket ctx ChangeCipherSpec
    liftIO $ contextFlush ctx
    cf <- usingState_ ctx getVersion >>= \ver -> usingHState ctx $ getHandshakeDigest ver role
    sendPacket ctx (Handshake [Finished cf])
    writeIORef (ctxFinished ctx) $ Just cf
    liftIO $ contextFlush ctx

recvChangeCipherAndFinish :: Context -> IO ()
recvChangeCipherAndFinish ctx = ETT__.tio "Network.TLS.Handshake.Common.recvChangeCipherAndFinish" ETT__.$ runRecvState ctx (RecvStateNext expectChangeCipher)
  where expectChangeCipher ChangeCipherSpec = return $ RecvStateHandshake expectFinish
        expectChangeCipher p                = unexpected (show p) (Just "change cipher")
        expectFinish (Finished _) = return RecvStateDone
        expectFinish p            = unexpected (show p) (Just "Handshake Finished")

data RecvState m =
      RecvStateNext (Packet -> m (RecvState m))
    | RecvStateHandshake (Handshake -> m (RecvState m))
    | RecvStateDone

recvPacketHandshake :: Context -> IO [Handshake]
recvPacketHandshake ctx = ETT__.tio "Network.TLS.Handshake.Common.recvPacketHandshake" ETT__.$ do
    pkts <- recvPacket ctx
    case pkts of
        Right (Handshake l) -> return l
        Right x@(AppData _) -> do
            -- If a TLS13 server decides to reject RTT0 data, the server should
            -- skip records for RTT0 data up to the maximum limit.
            established <- ctxEstablished ctx
            case established of
                EarlyDataNotAllowed n
                    | n > 0 -> do setEstablished ctx $ EarlyDataNotAllowed (n - 1)
                                  recvPacketHandshake ctx
                _           -> unexpected (show x) (Just "handshake")
        Right x             -> unexpected (show x) (Just "handshake")
        Left err            -> throwCore err

-- | process a list of handshakes message in the recv state machine.
onRecvStateHandshake :: Context -> RecvState IO -> [Handshake] -> IO (RecvState IO)
onRecvStateHandshake _   recvState [] = ETT__.tio "Network.TLS.Handshake.Common.onRecvStateHandshake" ETT__.$ return recvState
onRecvStateHandshake _   (RecvStateNext f) hms = ETT__.tio "Network.TLS.Handshake.Common.onRecvStateHandshake" ETT__.$ f (Handshake hms)
onRecvStateHandshake ctx (RecvStateHandshake f) (x:xs) = ETT__.tio "Network.TLS.Handshake.Common.onRecvStateHandshake" ETT__.$ do
    nstate <- f x
    processHandshake ctx x
    onRecvStateHandshake ctx nstate xs
onRecvStateHandshake _ _ _   = ETT__.tio "Network.TLS.Handshake.Common.onRecvStateHandshake" ETT__.$ unexpected "spurious handshake" Nothing

runRecvState :: Context -> RecvState IO -> IO ()
runRecvState _    RecvStateDone    = ETT__.tio "Network.TLS.Handshake.Common.runRecvState" ETT__.$ return ()
runRecvState ctx (RecvStateNext f) = ETT__.tio "Network.TLS.Handshake.Common.runRecvState" ETT__.$ recvPacket ctx >>= either throwCore f >>= runRecvState ctx
runRecvState ctx iniState          = ETT__.tio "Network.TLS.Handshake.Common.runRecvState" ETT__.$ recvPacketHandshake ctx >>= onRecvStateHandshake ctx iniState >>= runRecvState ctx

ensureRecvComplete :: MonadIO m => Context -> m ()
ensureRecvComplete ctx = ETT__.tm "Network.TLS.Handshake.Common.ensureRecvComplete" ETT__.$ do
    complete <- liftIO $ isRecvComplete ctx
    unless complete $
        throwCore $ Error_Protocol "received incomplete message at key change" UnexpectedMessage

processExtendedMasterSec :: MonadIO m => Context -> Version -> MessageType -> [ExtensionRaw] -> m Bool
processExtendedMasterSec ctx ver msgt exts
    | ver < TLS10  = ETT__.t "Network.TLS.Handshake.Common.processExtendedMasterSec" ETT__.$ return False
    | ver > TLS12  = ETT__.t "Network.TLS.Handshake.Common.processExtendedMasterSec" ETT__.$ error "EMS processing is not compatible with TLS 1.3"
    | ems == NoEMS = ETT__.t "Network.TLS.Handshake.Common.processExtendedMasterSec" ETT__.$ return False
    | otherwise    = ETT__.t "Network.TLS.Handshake.Common.processExtendedMasterSec" ETT__.$
        case extensionLookup extensionID_ExtendedMasterSecret exts >>= extensionDecode msgt of
            Just ExtendedMasterSecret -> usingHState ctx (setExtendedMasterSec True) >> return True
            Nothing | ems == RequireEMS -> throwCore $ Error_Protocol err HandshakeFailure
                    | otherwise -> return False
  where ems = supportedExtendedMasterSec (ctxSupported ctx)
        err = "peer does not support Extended Master Secret"

getSessionData :: Context -> IO (Maybe SessionData)
getSessionData ctx = ETT__.tio "Network.TLS.Handshake.Common.getSessionData" ETT__.$ do
    ver <- usingState_ ctx getVersion
    sni <- usingState_ ctx getClientSNI
    mms <- usingHState ctx (gets hstMasterSecret)
    !ems <- usingHState ctx getExtendedMasterSec
    tx  <- liftIO $ readMVar (ctxTxState ctx)
    alpn <- usingState_ ctx getNegotiatedProtocol
    let !cipher      = cipherID $ fromJust "cipher" $ stCipher tx
        !compression = compressionID $ stCompression tx
        flags = [SessionEMS | ems]
    case mms of
        Nothing -> return Nothing
        Just ms -> return $ Just SessionData
                        { sessionVersion     = ver
                        , sessionCipher      = cipher
                        , sessionCompression = compression
                        , sessionClientSNI   = sni
                        , sessionSecret      = ms
                        , sessionGroup       = Nothing
                        , sessionTicketInfo  = Nothing
                        , sessionALPN        = alpn
                        , sessionMaxEarlyDataSize = 0
                        , sessionFlags       = flags
                        }

extensionLookup :: ExtensionID -> [ExtensionRaw] -> Maybe ByteString
extensionLookup toFind = ETT__.t "Network.TLS.Handshake.Common.extensionLookup" ETT__.$ fmap (\(ExtensionRaw _ content) -> content)
                       . find (\(ExtensionRaw eid _) -> eid == toFind)

-- | Store the specified keypair.  Whether the public key and private key
-- actually match is left for the peer to discover.  We're not presently
-- burning  CPU to detect that misconfiguration.  We verify only that the
-- types of keys match and that it does not include an algorithm that would
-- not be safe.
storePrivInfo :: MonadIO m
              => Context
              -> CertificateChain
              -> PrivKey
              -> m PubKey
storePrivInfo ctx cc privkey = ETT__.tm "Network.TLS.Handshake.Common.storePrivInfo" ETT__.$ do
    let CertificateChain (c:_) = cc
        pubkey = certPubKey $ getCertificate c
    unless (isDigitalSignaturePair (pubkey, privkey)) $
        throwCore $ Error_Protocol "mismatched or unsupported private key pair" InternalError
    usingHState ctx $ setPublicPrivateKeys (pubkey, privkey)
    return pubkey

-- verify that the group selected by the peer is supported in the local
-- configuration
checkSupportedGroup :: Context -> Group -> IO ()
checkSupportedGroup ctx grp = ETT__.tio "Network.TLS.Handshake.Common.checkSupportedGroup" ETT__.$
    unless (isSupportedGroup ctx grp) $
        let msg = "unsupported (EC)DHE group: " ++ show grp
         in throwCore $ Error_Protocol msg IllegalParameter

isSupportedGroup :: Context -> Group -> Bool
isSupportedGroup ctx grp = ETT__.t "Network.TLS.Handshake.Common.isSupportedGroup" ETT__.$ grp `elem` supportedGroups (ctxSupported ctx)
