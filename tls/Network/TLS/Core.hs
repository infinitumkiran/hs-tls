{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# OPTIONS_HADDOCK hide #-}

module Network.TLS.Core (
    -- * Internal packet sending and receiving
    sendPacket12,
    recvPacket12,

    -- * Initialisation and Termination of context
    bye,
    handshake,

    -- * Application Layer Protocol Negotiation
    getNegotiatedProtocol,

    -- * Server Name Indication
    getClientSNI,

    -- * High level API
    sendData,
    recvData,
    recvData',
    updateKey,
    KeyUpdateRequest (..),
    requestCertificate,
) where

import qualified Control.Exception as E
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import Data.IORef
import System.Timeout

import Network.TLS.Cipher
import Network.TLS.Context
import Network.TLS.Crypto
import Network.TLS.Extension
import Network.TLS.Handshake
import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.KeySchedule
import Network.TLS.Parameters
import Network.TLS.PostHandshake
import Network.TLS.Session
import Network.TLS.State (getRole, getSession)
import qualified Network.TLS.State as S
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types (
    AnyTrafficSecret (..),
    ApplicationSecret,
    HostName,
    Role (..),
 )
import Network.TLS.Util (catchException, mapChunks_)
import Network.TLS.DebugLog (tlsDebug, tlsDebugSafeIO)

-- | Emit a @[TLS-DBG]@ line annotated with the connection's currently-negotiated
-- version/cipher.
--
-- 'contextGetInformation' is real I\/O that the instrumentation adds: it takes
-- 'ctxTLSState', 'ctxHandshakeState' and 'ctxRxRecordState' in turn (never
-- nested, so it cannot introduce a lock cycle) and it can throw, because
-- 'usingState_' turns a 'TLSError' into an exception.  'tlsDebugSafeIO' makes
-- the whole thing inert: a synchronous failure disappears, an asynchronous one
-- -- the 'System.Timeout.Timeout' from the post-handshake check in 'handshake',
-- or a 'Control.Concurrent.killThread' -- is re-thrown so the host's
-- cancellation still works.
--
-- Reentrancy: none of the call sites below holds any of those three MVars.
-- 'logRecvPacket' runs after @recvPacket12@\/@recvPacket13@ have returned, and
-- the @process@ cases run outside the state lock as well.
tlsDebugConn :: Context -> String -> IO ()
tlsDebugConn ctx ~label = tlsDebugSafeIO $ do
    minfo <- contextGetInformation ctx
    let vc = case minfo of
            Just i -> show (infoVersion i) ++ "/" ++ cipherName (infoCipher i)
            Nothing -> "no-negotiated-info"
    tlsDebug (label ++ " {" ++ vc ++ "}")

-- | Trace the outcome of a low-level packet receive.  The decisive signal for
-- the @NoResponseDataReceived@ investigation: @Left Error_EOF@ means the peer
-- closed the TCP connection with NO TLS alert (bare FIN) -- consistent with a
-- middlebox drop or a silent app-layer reject, and distinct from a fatal alert
-- (which names a reason, e.g. a client-cert rejection) or a graceful
-- @close_notify@.
--
-- The 'Either' argument is matched, so it is forced to WHNF here -- but every
-- caller binds it from @recvPacket*@ in a @do@ block under @Strict@, which has
-- already forced it, so no evaluation order changes.
logRecvPacket :: Context -> String -> Either TLSError p -> IO ()
logRecvPacket ctx tag (Left Error_EOF) =
    tlsDebugConn
        ctx
        (tag ++ ": recvPacket -> EOF (peer closed TCP with NO alert / bare FIN) -> this read returns \"\"")
logRecvPacket ctx tag (Left err) =
    tlsDebugConn ctx (tag ++ ": recvPacket -> error " ++ show err)
logRecvPacket _ _ (Right _) = return ()

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation.
-- Don't use this function as the acquire resource of 'bracket'.
handshake :: MonadIO m => Context -> m ()
handshake ctx = do
    handshake_ ctx
    liftIO $ tlsDebugConn ctx "handshake: completed"
    -- Trying to receive an alert of client authentication failure
    liftIO $ do
        role <- usingState_ ctx getRole
        tls13 <- tls13orLater ctx
        sentClientCert <- tls13stSentClientCert <$> getTLS13State ctx
        tlsDebug $
            "handshake: post-handshake auth-failure check"
                ++ " role="
                ++ show role
                ++ " tls13="
                ++ show tls13
                ++ " sentClientCert="
                ++ show sentClientCert
        when (role == ClientRole && tls13 && sentClientCert) $ do
            rtt <- getRTT ctx
            -- This 'timeout' should work.
            mdat <- timeout rtt $ recvData13 ctx
            case mdat of
                Nothing ->
                    -- Timed out waiting for an alert: server did NOT reject the
                    -- client cert within the RTT window (normal / good path).
                    tlsDebug "handshake: no client-auth-failure alert within RTT (client cert accepted so far)"
                Just dat -> do
                    -- Got something before we even sent a request.  If this is
                    -- empty, the server closed the connection right after the
                    -- TLS 1.3 handshake (typical mTLS client-cert rejection or a
                    -- middlebox drop) -> the eventual read returns "" ->
                    -- http-client raises NoResponseDataReceived.
                    tlsDebug $
                        "handshake: received "
                            ++ show (B.length dat)
                            ++ " bytes during post-handshake auth-failure window"
                            ++ (if B.null dat then " (EMPTY => peer closed after handshake; likely client-cert rejected / dropped)" else "")
                    modifyTLS13State ctx $ \st -> st{tls13stPendingRecvData = Just dat}

rttFactor :: Int
rttFactor = 3

getRTT :: Context -> IO Int
getRTT ctx = do
    rtt <- tls13stRTT <$> getTLS13State ctx
    let rtt' = max (fromIntegral rtt) 10
    return (rtt' * rttFactor * 1000) -- ms to us

-- | Notify the context that this side wants to close connection.
-- This is important that it is called before closing the handle, otherwise
-- the session might not be resumable (for version < TLS1.2).
-- This doesn't actually close the handle.
--
-- Proper usage is as follows:
--
-- > ctx <- contextNew <backend> <params>
-- > handshake ctx
-- > ...
-- > bye
--
-- The following code ensures nothing but is no harm.
--
-- > bracket (contextNew <backend> <params>) bye $ \ctx -> do
-- >   handshake ctx
-- >   ...
bye :: MonadIO m => Context -> m ()
bye ctx = liftIO $ do
    eof <- ctxEOF ctx
    tls13 <- tls13orLater ctx
    when (tls13 && not eof) $ do
        role <- usingState_ ctx getRole
        if role == ClientRole
            then do
                withWriteLock ctx $ sendCFifNecessary ctx
                -- receiving NewSessionTicket
                let chk = tls13stRecvNST <$> getTLS13State ctx
                recvNST <- chk
                unless recvNST $ do
                    rtt <- getRTT ctx
                    void $ timeout rtt $ recvHS13 ctx chk
            else do
                -- receiving Client Finished
                let chk = tls13stRecvCF <$> getTLS13State ctx
                recvCF <- chk
                unless recvCF $ do
                    -- no chance to measure RTT before receiving CF
                    -- fixme: 1sec is good enough?
                    let rtt = 1000000
                    void $ timeout rtt $ recvHS13 ctx chk
    bye_ ctx

bye_ :: MonadIO m => Context -> m ()
bye_ ctx = liftIO $ do
    -- Although setEOF is always protected by the read lock, here we don't try
    -- to wrap ctxEOF with it, so that function bye can still be called
    -- concurrently to a blocked recvData.
    eof <- ctxEOF ctx
    tls13 <- tls13orLater ctx
    unless eof $
        withWriteLock ctx $
            if tls13
                then sendPacket13 ctx $ Alert13 [(AlertLevel_Warning, CloseNotify)]
                else sendPacket12 ctx $ Alert [(AlertLevel_Warning, CloseNotify)]

-- | If the ALPN extensions have been used, this will
-- return get the protocol agreed upon.
getNegotiatedProtocol :: MonadIO m => Context -> m (Maybe B.ByteString)
getNegotiatedProtocol ctx = liftIO $ usingState_ ctx S.getNegotiatedProtocol

-- | If the Server Name Indication extension has been used, return the
-- hostname specified by the client.
getClientSNI :: MonadIO m => Context -> m (Maybe HostName)
getClientSNI ctx = liftIO $ usingState_ ctx S.getClientSNI

sendCFifNecessary :: Context -> IO ()
sendCFifNecessary ctx = do
    st <- getTLS13State ctx
    let recvSF = tls13stRecvSF st
        sentCF = tls13stSentCF st
    when (recvSF && not sentCF) $ do
        msend <- readIORef (ctxPendingSendAction ctx)
        case msend of
            Nothing -> return ()
            Just sendAction -> do
                sendAction ctx
                writeIORef (ctxPendingSendAction ctx) Nothing

-- | sendData sends a bunch of data.
-- It will automatically chunk data to acceptable packet size
sendData :: MonadIO m => Context -> L.ByteString -> m ()
sendData _ "" = return ()
sendData ctx dataToSend = liftIO $ do
    tls13 <- tls13orLater ctx
    let sendP bs
            | tls13 = do
                sendPacket13 ctx $ AppData13 bs
                role <- usingState_ ctx getRole
                sentCF <- tls13stSentCF <$> getTLS13State ctx
                rtt0 <- tls13st0RTT <$> getTLS13State ctx
                when (role == ClientRole && rtt0 && not sentCF) $
                    modifyTLS13State ctx $
                        \st -> st{tls13stPendingSentData = tls13stPendingSentData st . (bs :)}
            | otherwise = sendPacket12 ctx $ AppData bs
    when tls13 $ withWriteLock ctx $ sendCFifNecessary ctx
    withWriteLock ctx $ do
        checkValid ctx
        -- All chunks are protected with the same write lock because we don't
        -- want to interleave writes from other threads in the middle of our
        -- possibly large write.
        mlen <- getPeerRecordLimit ctx -- plaintext, dont' adjust for TLS 1.3
        mapM_ (mapChunks_ mlen sendP) (L.toChunks dataToSend)

-- | Get data out of Data packet, and automatically renegotiate if a Handshake
-- ClientHello is received.  An empty result means EOF.
recvData :: MonadIO m => Context -> m B.ByteString
recvData ctx = liftIO $ do
    tls13 <- tls13orLater ctx
    withReadLock ctx $ do
        -- On an already-closed connection, return "" (end of stream) instead of
        -- throwing.  http-client and similar consumers treat an empty read as a
        -- normal EOF; an exception here is otherwise surfaced as a request
        -- failure (e.g. HTTP 500) when a TLS 1.3 peer closes after its response
        -- and the caller reads once more.  This mirrors the "" already returned
        -- on the first CloseNotify.  Genuine (non-EOF) errors still throw from
        -- recvData12/recvData13 below.
        eofed <- ctxEOF ctx
        tlsDebugConn ctx ("recvData: entry tls13=" ++ show tls13 ++ " alreadyEOF=" ++ show eofed)
        if eofed
            then do
                tlsDebug "recvData: connection already EOF -> returning \"\" (=> http-client NoResponseDataReceived if this is the response read)"
                return B.empty
            else do
                checkValid ctx
                -- We protect with a read lock both reception and processing of the
                -- packet, because don't want another thread to receive a new packet
                -- before this one has been fully processed.
                --
                -- Even when recvData12/recvData13 loops, we only need to call
                -- function checkValid once.  Since we hold the read lock, no
                -- concurrent call will impact the validity of the context.
                if tls13 then recvData13 ctx else recvData12 ctx

recvData12 :: Context -> IO B.ByteString
recvData12 ctx = do
    pkt <- recvPacket12 ctx
    logRecvPacket ctx "recvData12" pkt
    either (onError terminate12) process pkt
  where
    process (Handshake [ch@ClientHello{}]) =
        handshakeWith ctx ch >> recvData12 ctx
    process (Handshake [hr@HelloRequest]) =
        handshakeWith ctx hr >> recvData12 ctx
    -- UserCanceled should be followed by a close_notify.
    -- fixme: is it safe to call recvData12?
    process (Alert [(AlertLevel_Warning, UserCanceled)]) = return B.empty
    process (Alert [(AlertLevel_Warning, CloseNotify)]) = do
        tlsDebugConn ctx "recvData12: received warning close_notify -> EOF, returning \"\""
        tryBye ctx >> setEOF ctx >> return B.empty
    process (Alert [(AlertLevel_Fatal, desc)]) = do
        tlsDebugConn ctx ("recvData12: received FATAL alert=" ++ show desc ++ " -> throwing Terminated")
        setEOF ctx
        E.throwIO
            ( Terminated
                True
                ("received fatal error: " ++ show desc)
                (Error_Protocol "remote side fatal error" desc)
            )

    -- when receiving empty appdata, we just retry to get some data.
    process (AppData "") = recvData12 ctx
    process (AppData x) = do
        tlsDebugConn ctx ("recvData12: received " ++ show (B.length x) ++ " bytes of application data")
        return x
    process p =
        let reason = "unexpected message " ++ show p
         in terminate12 (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

    terminate12 = terminateWithWriteLock ctx (sendPacket12 ctx . Alert)

recvData13 :: Context -> IO B.ByteString
recvData13 ctx = do
    mdat <- tls13stPendingRecvData <$> getTLS13State ctx
    case mdat of
        Nothing -> do
            pkt <- recvPacket13 ctx
            logRecvPacket ctx "recvData13" pkt
            either (onError (terminate13 ctx)) process pkt
        Just dat -> do
            tlsDebugConn ctx ("recvData13: replaying " ++ show (B.length dat) ++ " pending bytes buffered during post-handshake auth check")
            modifyTLS13State ctx $ \st -> st{tls13stPendingRecvData = Nothing}
            return dat
  where
    -- UserCanceled MUST be followed by a CloseNotify.
    process (Alert13 [(AlertLevel_Warning, UserCanceled)]) = return B.empty
    process (Alert13 [(AlertLevel_Warning, CloseNotify)]) = do
        tlsDebugConn ctx "recvData13: received warning close_notify -> EOF, returning \"\""
        tryBye ctx >> setEOF ctx >> return B.empty
    process (Alert13 [(AlertLevel_Fatal, desc)]) = do
        tlsDebugConn ctx ("recvData13: received FATAL alert=" ++ show desc ++ " -> throwing Terminated")
        setEOF ctx
        E.throwIO
            ( Terminated
                True
                ("received fatal error: " ++ show desc)
                (Error_Protocol "remote side fatal error" desc)
            )
    process (Handshake13 hs) = do
        loopHandshake13 hs
        recvData13 ctx
    -- when receiving empty appdata, we just retry to get some data.
    process (AppData13 "") = recvData13 ctx
    process (AppData13 x) = do
        let chunkLen = C8.length x
        tlsDebugConn ctx ("recvData13: received " ++ show chunkLen ++ " bytes of application data")
        established <- ctxEstablished ctx
        case established of
            EarlyDataAllowed maxSize
                | chunkLen <= maxSize -> do
                    setEstablished ctx $ EarlyDataAllowed (maxSize - chunkLen)
                    return x
                | otherwise ->
                    let reason = "early data overflow"
                     in terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            EarlyDataNotAllowed n
                | n > 0 -> do
                    setEstablished ctx $ EarlyDataNotAllowed (n - 1)
                    recvData13 ctx -- ignore "x"
                | otherwise ->
                    let reason = "early data deprotect overflow"
                     in terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            Established -> return x
            _ -> throwCore $ Error_Protocol "data at not-established" UnexpectedMessage
    process ChangeCipherSpec13 = do
        established <- ctxEstablished ctx
        if established /= Established
            then recvData13 ctx
            else do
                let reason = "CSS after Finished"
                terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
    process p =
        let reason = "unexpected message " ++ show p
         in terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

    loopHandshake13 [] = return ()
    -- fixme: some implementations send multiple NST at the same time.
    -- Only the first one is used at this moment.
    loopHandshake13 (NewSessionTicket13 life add nonce ticket exts : hs) = do
        role <- usingState_ ctx S.getRole
        unless (role == ClientRole) $
            let reason = "Session ticket is allowed for client only"
             in terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        -- This part is similar to handshake code, so protected with
        -- read+write locks (which is also what we use for all calls to the
        -- session manager).
        withWriteLock ctx $ do
            Just resumptionSecret <- usingHState ctx getTLS13ResumptionSecret
            (_, usedCipher, _, _) <- getTxRecordState ctx
            -- mMaxSize is always Just, but anyway
            let extract (EarlyDataIndication mMaxSize) =
                    maybe 0 (fromIntegral . safeNonNegative32) mMaxSize
            let choice = makeCipherChoice TLS13 usedCipher
                psk = derivePSK choice resumptionSecret nonce
                maxSize =
                    lookupAndDecode
                        EID_EarlyData
                        MsgTNewSessionTicket
                        exts
                        0
                        extract
                life7d = min life 604800 -- 7 days max
            tinfo <- createTLS13TicketInfo life7d (Right add) Nothing
            sdata <- getSessionData13 ctx usedCipher tinfo maxSize psk
            let ticket' = B.copy ticket
            void $ sessionEstablish (sharedSessionManager $ ctxShared ctx) ticket' sdata
            modifyTLS13State ctx $ \st -> st{tls13stRecvNST = True}
        loopHandshake13 hs
    loopHandshake13 (KeyUpdate13 mode : hs) = do
        let multipleKeyUpdate = any isKeyUpdate13 hs
        when multipleKeyUpdate $ do
            let reason = "Multiple KeyUpdate is not allowed in one record"
            terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        when (ctxQUICMode ctx) $ do
            let reason = "KeyUpdate is not allowed for QUIC"
            terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        checkAlignment ctx hs
        established <- ctxEstablished ctx
        -- Though RFC 8446 Sec 4.6.3 does not clearly says,
        -- unidirectional key update is legal.
        -- So, we don't have to check if this key update is corresponding
        -- to key update (update_requested) which we sent.
        if established == Established
            then do
                keyUpdate ctx getRxRecordState setRxRecordState
                -- Write lock wraps both actions because we don't want another
                -- packet to be sent by another thread before the Tx state is
                -- updated.
                when (mode == UpdateRequested) $ withWriteLock ctx $ do
                    sendPacket13 ctx $ Handshake13 [KeyUpdate13 UpdateNotRequested]
                    keyUpdate ctx getTxRecordState setTxRecordState
                loopHandshake13 hs
            else do
                let reason = "received key update before established"
                terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
    loopHandshake13 (h@CertRequest13{} : hs) =
        postHandshakeAuthWith ctx h >> loopHandshake13 hs
    loopHandshake13 (h@Certificate13{} : hs) =
        postHandshakeAuthWith ctx h >> loopHandshake13 hs
    loopHandshake13 (h : hs) = do
        rtt0 <- tls13st0RTT <$> getTLS13State ctx
        when rtt0 $ case h of
            ServerHello13 srand _ _ _ ->
                when (isHelloRetryRequest srand) $ do
                    clearTxRecordState ctx
                    let reason = "HRR is not allowed for 0-RTT"
                     in terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
            _ -> return ()
        cont <- popAction ctx h hs
        when cont $ loopHandshake13 hs

recvHS13 :: Context -> IO Bool -> IO ()
recvHS13 ctx breakLoop = do
    pkt <- recvPacket13 ctx
    -- fixme: Left
    either (\_ -> return ()) process pkt
  where
    -- UserCanceled MUST be followed by a CloseNotify.
    process (Alert13 [(AlertLevel_Warning, CloseNotify)]) = tryBye ctx >> setEOF ctx
    process (Alert13 [(AlertLevel_Fatal, _desc)]) = setEOF ctx
    process (Handshake13 hs) = do
        loopHandshake13 hs
        stop <- breakLoop
        unless stop $ recvHS13 ctx breakLoop
    process _ = recvHS13 ctx breakLoop

    loopHandshake13 [] = return ()
    -- fixme: some implementations send multiple NST at the same time.
    -- Only the first one is used at this moment.
    loopHandshake13 (NewSessionTicket13 life add nonce ticket exts : hs) = do
        role <- usingState_ ctx S.getRole
        unless (role == ClientRole) $
            let reason = "Session ticket is allowed for client only"
             in terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason
        -- This part is similar to handshake code, so protected with
        -- read+write locks (which is also what we use for all calls to the
        -- session manager).
        withWriteLock ctx $ do
            Just resumptionSecret <- usingHState ctx getTLS13ResumptionSecret
            (_, usedCipher, _, _) <- getTxRecordState ctx
            let choice = makeCipherChoice TLS13 usedCipher
                psk = derivePSK choice resumptionSecret nonce
                maxSize =
                    lookupAndDecode
                        EID_EarlyData
                        MsgTNewSessionTicket
                        exts
                        0
                        (\(EarlyDataIndication mms) -> fromIntegral $ safeNonNegative32 $ fromJust mms)
                life7d = min life 604800 -- 7 days max
            tinfo <- createTLS13TicketInfo life7d (Right add) Nothing
            sdata <- getSessionData13 ctx usedCipher tinfo maxSize psk
            let ticket' = B.copy ticket
            void $ sessionEstablish (sharedSessionManager $ ctxShared ctx) ticket' sdata
            modifyTLS13State ctx $ \st -> st{tls13stRecvNST = True}
        loopHandshake13 hs
    loopHandshake13 (h : hs) = do
        cont <- popAction ctx h hs
        when cont $ loopHandshake13 hs

terminate13
    :: Context -> TLSError -> AlertLevel -> AlertDescription -> String -> IO a
terminate13 ctx = terminateWithWriteLock ctx (sendPacket13 ctx . Alert13)

popAction :: Context -> Handshake13 -> [Handshake13] -> IO Bool
popAction ctx h hs = do
    mPendingRecvAction <- popPendingRecvAction ctx
    case mPendingRecvAction of
        Nothing -> return False
        Just action -> do
            -- Pending actions are executed with read+write locks, just
            -- like regular handshake code.
            withWriteLock ctx $
                handleException ctx $ do
                    case action of
                        PendingRecvAction needAligned pa -> do
                            when needAligned $ checkAlignment ctx hs
                            processHandshake13 ctx h
                            pa h
                        PendingRecvActionHash needAligned pa -> do
                            when needAligned $ checkAlignment ctx hs
                            d <- transcriptHash ctx
                            processHandshake13 ctx h
                            pa d h
                    -- Client: after receiving SH, app data is coming.
                    -- this loop tries to receive it.
                    -- App key must be installed before receiving
                    -- the app data.
                    sendCFifNecessary ctx
            return True

checkAlignment :: Context -> [Handshake13] -> IO ()
checkAlignment ctx _hs = do
    complete <- isRecvComplete ctx
    unless complete $ do
        let reason = "received message not aligned with record boundary"
        terminate13 ctx (Error_Misc reason) AlertLevel_Fatal UnexpectedMessage reason

-- the other side could have close the connection already, so wrap
-- this in a try and ignore all exceptions
tryBye :: Context -> IO ()
tryBye ctx = catchException (bye_ ctx) (\_ -> return ())

onError
    :: Monad m
    => (TLSError -> AlertLevel -> AlertDescription -> String -> m B.ByteString)
    -> TLSError
    -> m B.ByteString
onError _ Error_EOF =
    -- Not really an error.
    return B.empty
onError terminate err =
    let (lvl, ad) = errorToAlert err
     in terminate err lvl ad (errorToAlertMessage err)

terminateWithWriteLock
    :: Context
    -> ([(AlertLevel, AlertDescription)] -> IO ())
    -> TLSError
    -> AlertLevel
    -> AlertDescription
    -> String
    -> IO a
terminateWithWriteLock ctx send err level desc reason = withWriteLock ctx $ do
    tls13 <- tls13orLater ctx
    unless tls13 $ do
        -- TLS 1.2 uses the same session ID and session data
        -- for all resumed sessions.
        --
        -- TLS 1.3 changes session data for every resumed session.
        session <- usingState_ ctx getSession
        case session of
            Session Nothing -> return ()
            Session (Just sid) ->
                -- calling even session ticket manager anyway
                sessionInvalidate (sharedSessionManager $ ctxShared ctx) sid
    catchException (send [(level, desc)]) (\_ -> return ())
    setEOF ctx
    E.throwIO (Terminated False reason err)

{-# DEPRECATED recvData' "use recvData that returns strict bytestring" #-}

-- | same as recvData but returns a lazy bytestring.
recvData' :: MonadIO m => Context -> m L.ByteString
recvData' ctx = L.fromChunks . (: []) <$> recvData ctx

keyUpdate
    :: Context
    -> (Context -> IO (Hash, Cipher, CryptLevel, C8.ByteString))
    -> (Context -> Hash -> Cipher -> AnyTrafficSecret ApplicationSecret -> IO ())
    -> IO ()
keyUpdate ctx getState setState = do
    (usedHash, usedCipher, level, applicationSecretN) <- getState ctx
    unless (level == CryptApplicationSecret) $
        throwCore $
            Error_Protocol
                "tried key update without application traffic secret"
                InternalError
    let applicationSecretN1 =
            hkdfExpandLabel usedHash applicationSecretN "traffic upd" "" $
                hashDigestSize usedHash
    setState ctx usedHash usedCipher (AnyTrafficSecret applicationSecretN1)

-- | How to update keys in TLS 1.3
data KeyUpdateRequest
    = -- | Unidirectional key update
      OneWay
    | -- | Bidirectional key update (normal case)
      TwoWay
    deriving (Eq, Show)

-- | Updating appication traffic secrets for TLS 1.3.
--   If this API is called for TLS 1.3, 'True' is returned.
--   Otherwise, 'False' is returned.
updateKey :: MonadIO m => Context -> KeyUpdateRequest -> m Bool
updateKey ctx way = liftIO $ do
    tls13 <- tls13orLater ctx
    when tls13 $ do
        let req = case way of
                OneWay -> UpdateNotRequested
                TwoWay -> UpdateRequested
        -- Write lock wraps both actions because we don't want another packet to
        -- be sent by another thread before the Tx state is updated.
        withWriteLock ctx $ do
            sendPacket13 ctx $ Handshake13 [KeyUpdate13 req]
            keyUpdate ctx getTxRecordState setTxRecordState
    return tls13
