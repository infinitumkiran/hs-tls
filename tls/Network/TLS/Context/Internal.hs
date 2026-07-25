{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
-- |
-- Module      : Network.TLS.Context.Internal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Context.Internal
    (
    -- * Context configuration
      ClientParams(..)
    , ServerParams(..)
    , defaultParamsClient
    , SessionID
    , SessionData(..)
    , MaxFragmentEnum(..)
    , Measurement(..)

    -- * Context object and accessor
    , Context(..)
    , Hooks(..)
    , Established(..)
    , PendingAction(..)
    , ctxEOF
    , ctxHasSSLv2ClientHello
    , ctxDisableSSLv2ClientHello
    , ctxEstablished
    , withLog
    , ctxWithHooks
    , contextModifyHooks
    , setEOF
    , setEstablished
    , contextFlush
    , contextClose
    , contextSend
    , contextRecv
    , updateRecordLayer
    , updateMeasure
    , withMeasure
    , withReadLock
    , withWriteLock
    , withStateLock
    , withRWLock

    -- * information
    , Information(..)
    , contextGetInformation

    -- * Using context states
    , throwCore
    , failOnEitherError
    , usingState
    , usingState_
    , runTxState
    , runRxState
    , usingHState
    , getHState
    , saveHState
    , restoreHState
    , getStateRNG
    , tls13orLater
    , addCertRequest13
    , getCertRequest13
    , decideRecordVersion

    -- * Misc
    , HandshakeSync(..)
    ) where

import Network.TLS.Backend
import Network.TLS.Cipher
import Network.TLS.Compression (Compression)
import Network.TLS.Extension
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.State
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Measurement
import Network.TLS.Parameters
import Network.TLS.Record.Layer
import Network.TLS.Record.State
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.Util

import Control.Concurrent.MVar
import Control.Exception (throwIO)
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef
import Data.Tuple
import qualified Debug.EulerTrace.Tls as ETT__

-- | Information related to a running context, e.g. current cipher
data Information = Information
    { infoVersion      :: Version
    , infoCipher       :: Cipher
    , infoCompression  :: Compression
    , infoMasterSecret :: Maybe ByteString
    , infoExtendedMasterSec   :: Bool
    , infoClientRandom :: Maybe ClientRandom
    , infoServerRandom :: Maybe ServerRandom
    , infoNegotiatedGroup     :: Maybe Group
    , infoTLS13HandshakeMode  :: Maybe HandshakeMode13
    , infoIsEarlyDataAccepted :: Bool
    } deriving (Show,Eq)

-- | A TLS Context keep tls specific state, parameters and backend information.
data Context = forall bytes . Monoid bytes => Context
    { ctxConnection       :: Backend   -- ^ return the backend object associated with this context
    , ctxSupported        :: Supported
    , ctxShared           :: Shared
    , ctxState            :: MVar TLSState
    , ctxMeasurement      :: IORef Measurement
    , ctxEOF_             :: IORef Bool    -- ^ has the handle EOFed or not.
    , ctxEstablished_     :: IORef Established -- ^ has the handshake been done and been successful.
    , ctxNeedEmptyPacket  :: IORef Bool    -- ^ empty packet workaround for CBC guessability.
    , ctxSSLv2ClientHello :: IORef Bool    -- ^ enable the reception of compatibility SSLv2 client hello.
                                           -- the flag will be set to false regardless of its initial value
                                           -- after the first packet received.
    , ctxFragmentSize     :: Maybe Int        -- ^ maximum size of plaintext fragments
    , ctxTxState          :: MVar RecordState -- ^ current tx state
    , ctxRxState          :: MVar RecordState -- ^ current rx state
    , ctxHandshake        :: MVar (Maybe HandshakeState) -- ^ optional handshake state
    , ctxDoHandshake      :: Context -> IO ()
    , ctxDoHandshakeWith  :: Context -> Handshake -> IO ()
    , ctxDoRequestCertificate :: Context -> IO Bool
    , ctxDoPostHandshakeAuthWith :: Context -> Handshake13 -> IO ()
    , ctxHooks            :: IORef Hooks   -- ^ hooks for this context
    , ctxLockWrite        :: MVar ()       -- ^ lock to use for writing data (including updating the state)
    , ctxLockRead         :: MVar ()       -- ^ lock to use for reading data (including updating the state)
    , ctxLockState        :: MVar ()       -- ^ lock used during read/write when receiving and sending packet.
                                           -- it is usually nested in a write or read lock.
    , ctxPendingActions   :: IORef [PendingAction]
    , ctxCertRequests     :: IORef [Handshake13]  -- ^ pending PHA requests
    , ctxKeyLogger        :: String -> IO ()
    , ctxRecordLayer      :: RecordLayer bytes
    , ctxHandshakeSync    :: HandshakeSync
    , ctxQUICMode         :: Bool
    , ctxFinished         :: IORef (Maybe FinishedData)
    , ctxPeerFinished     :: IORef (Maybe FinishedData)
    }

data HandshakeSync = HandshakeSync (Context -> ClientState -> IO ())
                                   (Context -> ServerState -> IO ())

updateRecordLayer :: Monoid bytes => RecordLayer bytes -> Context -> Context
updateRecordLayer recordLayer Context{..} = ETT__.t "Network.TLS.Context.Internal.updateRecordLayer" ETT__.$
    Context { ctxRecordLayer = recordLayer, .. }

data Established = NotEstablished
                 | EarlyDataAllowed Int    -- remaining 0-RTT bytes allowed
                 | EarlyDataNotAllowed Int -- remaining 0-RTT packets allowed to skip
                 | Established
                 deriving (Eq, Show)

data PendingAction
    = PendingAction Bool (Handshake13 -> IO ())
      -- ^ simple pending action
    | PendingActionHash Bool (ByteString -> Handshake13 -> IO ())
      -- ^ pending action taking transcript hash up to preceding message

updateMeasure :: Context -> (Measurement -> Measurement) -> IO ()
updateMeasure ctx = ETT__.t "Network.TLS.Context.Internal.updateMeasure" ETT__.$ modifyIORef' (ctxMeasurement ctx)

withMeasure :: Context -> (Measurement -> IO a) -> IO a
withMeasure ctx f = ETT__.tio "Network.TLS.Context.Internal.withMeasure" ETT__.$ readIORef (ctxMeasurement ctx) >>= f

-- | A shortcut for 'backendFlush . ctxConnection'.
contextFlush :: Context -> IO ()
contextFlush = ETT__.t "Network.TLS.Context.Internal.contextFlush" ETT__.$ backendFlush . ctxConnection

-- | A shortcut for 'backendClose . ctxConnection'.
contextClose :: Context -> IO ()
contextClose = ETT__.t "Network.TLS.Context.Internal.contextClose" ETT__.$ backendClose . ctxConnection

-- | Information about the current context
contextGetInformation :: Context -> IO (Maybe Information)
contextGetInformation ctx = ETT__.tio "Network.TLS.Context.Internal.contextGetInformation" ETT__.$ do
    ver    <- usingState_ ctx $ gets stVersion
    hstate <- getHState ctx
    let (ms, ems, cr, sr, hm13, grp) =
            case hstate of
                Just st -> (hstMasterSecret st,
                            hstExtendedMasterSec st,
                            Just (hstClientRandom st),
                            hstServerRandom st,
                            if ver == Just TLS13 then Just (hstTLS13HandshakeMode st) else Nothing,
                            hstNegotiatedGroup st)
                Nothing -> (Nothing, False, Nothing, Nothing, Nothing, Nothing)
    (cipher,comp) <- readMVar (ctxRxState ctx) <&> \st -> (stCipher st, stCompression st)
    let accepted = case hstate of
            Just st -> hstTLS13RTT0Status st == RTT0Accepted
            Nothing -> False
    case (ver, cipher) of
        (Just v, Just c) -> return $ Just $ Information v c comp ms ems cr sr grp hm13 accepted
        _                -> return Nothing

contextSend :: Context -> ByteString -> IO ()
contextSend c b = ETT__.tio "Network.TLS.Context.Internal.contextSend" ETT__.$ updateMeasure c (addBytesSent $ B.length b) >> (backendSend $ ctxConnection c) b

contextRecv :: Context -> Int -> IO ByteString
contextRecv c sz = ETT__.tio "Network.TLS.Context.Internal.contextRecv" ETT__.$ updateMeasure c (addBytesReceived sz) >> (backendRecv $ ctxConnection c) sz

ctxEOF :: Context -> IO Bool
ctxEOF ctx = ETT__.tio "Network.TLS.Context.Internal.ctxEOF" ETT__.$ readIORef $ ctxEOF_ ctx

ctxHasSSLv2ClientHello :: Context -> IO Bool
ctxHasSSLv2ClientHello ctx = ETT__.tio "Network.TLS.Context.Internal.ctxHasSSLv2ClientHello" ETT__.$ readIORef $ ctxSSLv2ClientHello ctx

ctxDisableSSLv2ClientHello :: Context -> IO ()
ctxDisableSSLv2ClientHello ctx = ETT__.tio "Network.TLS.Context.Internal.ctxDisableSSLv2ClientHello" ETT__.$ writeIORef (ctxSSLv2ClientHello ctx) False

setEOF :: Context -> IO ()
setEOF ctx = ETT__.tio "Network.TLS.Context.Internal.setEOF" ETT__.$ writeIORef (ctxEOF_ ctx) True

ctxEstablished :: Context -> IO Established
ctxEstablished ctx = ETT__.tio "Network.TLS.Context.Internal.ctxEstablished" ETT__.$ readIORef $ ctxEstablished_ ctx

ctxWithHooks :: Context -> (Hooks -> IO a) -> IO a
ctxWithHooks ctx f = ETT__.tio "Network.TLS.Context.Internal.ctxWithHooks" ETT__.$ readIORef (ctxHooks ctx) >>= f

contextModifyHooks :: Context -> (Hooks -> Hooks) -> IO ()
contextModifyHooks ctx = ETT__.t "Network.TLS.Context.Internal.contextModifyHooks" ETT__.$ modifyIORef (ctxHooks ctx)

setEstablished :: Context -> Established -> IO ()
setEstablished ctx = ETT__.t "Network.TLS.Context.Internal.setEstablished" ETT__.$ writeIORef (ctxEstablished_ ctx)

withLog :: Context -> (Logging -> IO ()) -> IO ()
withLog ctx f = ETT__.tio "Network.TLS.Context.Internal.withLog" ETT__.$ ctxWithHooks ctx (f . hookLogging)

throwCore :: MonadIO m => TLSError -> m a
throwCore = ETT__.t "Network.TLS.Context.Internal.throwCore" ETT__.$ liftIO . throwIO . Uncontextualized

failOnEitherError :: MonadIO m => m (Either TLSError a) -> m a
failOnEitherError f = ETT__.tm "Network.TLS.Context.Internal.failOnEitherError" ETT__.$ do
    ret <- f
    case ret of
        Left err -> throwCore err
        Right r  -> return r

usingState :: Context -> TLSSt a -> IO (Either TLSError a)
usingState ctx f = ETT__.tio "Network.TLS.Context.Internal.usingState" ETT__.$
    modifyMVar (ctxState ctx) $ \st ->
            let (a, newst) = runTLSState f st
             in newst `seq` return (newst, a)

usingState_ :: Context -> TLSSt a -> IO a
usingState_ ctx f = ETT__.tio "Network.TLS.Context.Internal.usingState_" ETT__.$ failOnEitherError $ usingState ctx f

usingHState :: MonadIO m => Context -> HandshakeM a -> m a
usingHState ctx f = ETT__.tm "Network.TLS.Context.Internal.usingHState" ETT__.$ liftIO $ modifyMVar (ctxHandshake ctx) $ \mst ->
    case mst of
        Nothing -> liftIO $ throwIO $ MissingHandshake
        Just st -> return $ swap (Just <$> runHandshake st f)

getHState :: MonadIO m => Context -> m (Maybe HandshakeState)
getHState ctx = ETT__.tm "Network.TLS.Context.Internal.getHState" ETT__.$ liftIO $ readMVar (ctxHandshake ctx)

saveHState :: Context -> IO (Saved (Maybe HandshakeState))
saveHState ctx = ETT__.tio "Network.TLS.Context.Internal.saveHState" ETT__.$ saveMVar (ctxHandshake ctx)

restoreHState :: Context
              -> Saved (Maybe HandshakeState)
              -> IO (Saved (Maybe HandshakeState))
restoreHState ctx = ETT__.t "Network.TLS.Context.Internal.restoreHState" ETT__.$ restoreMVar (ctxHandshake ctx)

decideRecordVersion :: Context -> IO (Version, Bool)
decideRecordVersion ctx = ETT__.tio "Network.TLS.Context.Internal.decideRecordVersion" ETT__.$ usingState_ ctx $ do
    ver <- getVersionWithDefault (maximum $ supportedVersions $ ctxSupported ctx)
    hrr <- getTLS13HRR
    -- For TLS 1.3, ver' is only used in ClientHello.
    -- The record version of the first ClientHello SHOULD be TLS 1.0.
    -- The record version of the second ClientHello MUST be TLS 1.2.
    let ver'
         | ver >= TLS13 = if hrr then TLS12 else TLS10
         | otherwise    = ver
    return (ver', ver >= TLS13)

runTxState :: Context -> RecordM a -> IO (Either TLSError a)
runTxState ctx f = ETT__.tio "Network.TLS.Context.Internal.runTxState" ETT__.$ do
    (ver, tls13) <- decideRecordVersion ctx
    let opt = RecordOptions { recordVersion = ver
                            , recordTLS13   = tls13
                            }
    modifyMVar (ctxTxState ctx) $ \st ->
        case runRecordM f opt st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

runRxState :: Context -> RecordM a -> IO (Either TLSError a)
runRxState ctx f = ETT__.tio "Network.TLS.Context.Internal.runRxState" ETT__.$ do
    ver <- usingState_ ctx getVersion
    -- For 1.3, ver is just ignored. So, it is not necessary to convert ver.
    let opt = RecordOptions { recordVersion = ver
                            , recordTLS13   = ver >= TLS13
                            }
    modifyMVar (ctxRxState ctx) $ \st ->
        case runRecordM f opt st of
            Left err         -> return (st, Left err)
            Right (a, newSt) -> return (newSt, Right a)

getStateRNG :: Context -> Int -> IO ByteString
getStateRNG ctx n = ETT__.tio "Network.TLS.Context.Internal.getStateRNG" ETT__.$ usingState_ ctx $ genRandom n

withReadLock :: Context -> IO a -> IO a
withReadLock ctx f = ETT__.tio "Network.TLS.Context.Internal.withReadLock" ETT__.$ withMVar (ctxLockRead ctx) (const f)

withWriteLock :: Context -> IO a -> IO a
withWriteLock ctx f = ETT__.tio "Network.TLS.Context.Internal.withWriteLock" ETT__.$ withMVar (ctxLockWrite ctx) (const f)

withRWLock :: Context -> IO a -> IO a
withRWLock ctx f = ETT__.tio "Network.TLS.Context.Internal.withRWLock" ETT__.$ withReadLock ctx $ withWriteLock ctx f

withStateLock :: Context -> IO a -> IO a
withStateLock ctx f = ETT__.tio "Network.TLS.Context.Internal.withStateLock" ETT__.$ withMVar (ctxLockState ctx) (const f)

tls13orLater :: MonadIO m => Context -> m Bool
tls13orLater ctx = ETT__.tm "Network.TLS.Context.Internal.tls13orLater" ETT__.$ do
    ev <- liftIO $ usingState ctx $ getVersionWithDefault TLS10 -- fixme
    return $ case ev of
               Left  _ -> False
               Right v -> v >= TLS13

addCertRequest13 :: Context -> Handshake13 -> IO ()
addCertRequest13 ctx certReq = ETT__.tio "Network.TLS.Context.Internal.addCertRequest13" ETT__.$ modifyIORef (ctxCertRequests ctx) (certReq:)

getCertRequest13 :: Context -> CertReqContext -> IO (Maybe Handshake13)
getCertRequest13 ctx context = ETT__.tio "Network.TLS.Context.Internal.getCertRequest13" ETT__.$ do
    let ref = ctxCertRequests ctx
    l <- readIORef ref
    let (matched, others) = partition (\(CertRequest13 c _) -> context == c) l
    case matched of
        []          -> return Nothing
        (certReq:_) -> writeIORef ref others >> return (Just certReq)
