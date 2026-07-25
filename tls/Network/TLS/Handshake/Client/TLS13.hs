{-# LANGUAGE OverloadedStrings #-}

module Network.TLS.Handshake.Client.TLS13 (
    recvServerSecondFlight13,
    sendClientSecondFlight13,
    asyncServerHello13,
    postHandshakeAuthClientWith,
) where

import Control.Exception (bracket)
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import Data.IORef

import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Crypto
import Network.TLS.DebugLog
import Network.TLS.Extension
import Network.TLS.Handshake.Client.Common
import Network.TLS.Handshake.Client.ServerHello
import Network.TLS.Handshake.Common hiding (expectFinished)
import Network.TLS.Handshake.Common13
import Network.TLS.Handshake.Control
import Network.TLS.Handshake.Key
import Network.TLS.Handshake.Process
import Network.TLS.Handshake.Signature
import Network.TLS.Handshake.State
import Network.TLS.Handshake.State13
import Network.TLS.IO
import Network.TLS.Imports
import Network.TLS.Packet13 (compressCertificate13)
import Network.TLS.Parameters
import Network.TLS.State
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Types
import Network.TLS.X509

----------------------------------------------------------------
----------------------------------------------------------------

recvServerSecondFlight13 :: ClientParams -> Context -> Maybe Group -> IO ()
recvServerSecondFlight13 cparams ctx groupSent = do
    resuming <- prepareSecondFlight13 ctx groupSent
    runRecvHandshake13 $ do
        recvHandshake13 ctx $ expectEncryptedExtensions ctx
        unless resuming $ recvHandshake13 ctx $ expectCertRequest cparams ctx
        recvHandshake13hash ctx $ expectFinished cparams ctx

----------------------------------------------------------------

prepareSecondFlight13
    :: Context -> Maybe Group -> IO Bool
prepareSecondFlight13 ctx groupSent = do
    choice <- makeCipherChoice TLS13 <$> usingHState ctx getPendingCipher
    prepareSecondFlight13' ctx groupSent choice

prepareSecondFlight13'
    :: Context
    -> Maybe Group
    -> CipherChoice
    -> IO Bool
prepareSecondFlight13' ctx groupSent choice = do
    (_, hkey, resuming) <- switchToHandshakeSecret
    let clientHandshakeSecret = triClient hkey
        serverHandshakeSecret = triServer hkey
        handSecInfo = HandshakeSecretInfo usedCipher (clientHandshakeSecret, serverHandshakeSecret)
    contextSync ctx $ RecvServerHello handSecInfo
    modifyTLS13State ctx $ \st ->
        st
            { tls13stChoice = choice
            , tls13stHsKey = Just hkey
            }
    return resuming
  where
    usedCipher = cCipher choice
    usedHash = cHash choice

    hashSize = hashDigestSize usedHash

    switchToHandshakeSecret = do
        ensureRecvComplete ctx
        ecdhe <- calcSharedKey
        (earlySecret, resuming) <- makeEarlySecret
        handKey <- calculateHandshakeSecret ctx choice earlySecret ecdhe
        let serverHandshakeSecret = triServer handKey
        setRxRecordState ctx usedHash usedCipher serverHandshakeSecret
        return (usedCipher, handKey, resuming)

    calcSharedKey = do
        serverKeyShare <- do
            mks <- usingState_ ctx getTLS13KeyShare
            case mks of
                Just (KeyShareServerHello ks) -> return ks
                Just _ ->
                    throwCore $ Error_Protocol "invalid key_share value" IllegalParameter
                Nothing ->
                    throwCore $
                        Error_Protocol
                            "key exchange not implemented, expected key_share extension"
                            HandshakeFailure
        let grp = keyShareEntryGroup serverKeyShare
        unless (checkKeyShareKeyLength serverKeyShare) $
            throwCore $
                Error_Protocol "broken key_share" IllegalParameter
        unless (groupSent == Just grp) $
            throwCore $
                Error_Protocol "received incompatible group for (EC)DHE" IllegalParameter
        usingHState ctx $ setSupportedGroup grp
        usingHState ctx getGroupPrivate >>= fromServerKeyShare serverKeyShare

    makeEarlySecret = do
        mEarlySecretPSK <- usingHState ctx getTLS13EarlySecret
        case mEarlySecretPSK of
            Nothing -> return (initEarlySecret choice Nothing, False)
            Just earlySecretPSK@(BaseSecret sec) -> do
                mSelectedIdentity <- usingState_ ctx getTLS13PreSharedKey
                case mSelectedIdentity of
                    Nothing ->
                        return (initEarlySecret choice Nothing, False)
                    Just (PreSharedKeyServerHello 0) -> do
                        unless (B.length sec == hashSize) $
                            throwCore $
                                Error_Protocol
                                    "selected cipher is incompatible with selected PSK"
                                    IllegalParameter
                        usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                        return (earlySecretPSK, True)
                    Just _ ->
                        throwCore $ Error_Protocol "selected identity out of range" IllegalParameter

----------------------------------------------------------------

expectEncryptedExtensions
    :: MonadIO m => Context -> Handshake13 -> m ()
expectEncryptedExtensions ctx (EncryptedExtensions13 eexts) = do
    liftIO $ do
        setALPN ctx MsgTEncryptedExtensions eexts
        modifyTLS13State ctx $ \st -> st{tls13stClientExtensions = eexts}
    st13 <- usingHState ctx getTLS13RTT0Status
    when (st13 == RTT0Sent) $
        case extensionLookup EID_EarlyData eexts of
            Just _ -> do
                usingHState ctx $ setTLS13HandshakeMode RTT0
                usingHState ctx $ setTLS13RTT0Status RTT0Accepted
                liftIO $ modifyTLS13State ctx $ \st -> st{tls13st0RTTAccepted = True}
            Nothing -> do
                usingHState ctx $ setTLS13HandshakeMode PreSharedKey
                usingHState ctx $ setTLS13RTT0Status RTT0Rejected
expectEncryptedExtensions _ p = unexpected (show p) (Just "encrypted extensions")

----------------------------------------------------------------
-- not used in 0-RTT
expectCertRequest
    :: MonadIO m => ClientParams -> Context -> Handshake13 -> RecvHandshake13M m ()
expectCertRequest cparams ctx (CertRequest13 token exts) = do
    processCertRequest13 ctx token exts
    recvHandshake13 ctx $ expectCertAndVerify cparams ctx
expectCertRequest cparams ctx other = do
    usingHState ctx $ do
        setCertReqToken Nothing
        setCertReqCBdata Nothing
    -- setCertReqSigAlgsCert Nothing
    expectCertAndVerify cparams ctx other

processCertRequest13
    :: MonadIO m => Context -> CertReqContext -> [ExtensionRaw] -> m ()
processCertRequest13 ctx token exts = do
    let hsextID = EID_SignatureAlgorithms
    -- caextID = EID_SignatureAlgorithmsCert
    dNames <- canames
    -- The @signature_algorithms@ extension is mandatory.
    hsAlgs <- extalgs hsextID unsighash
    cTypes <- case hsAlgs of
        Just as ->
            let validAs = filter isHashSignatureValid13 as
             in return $ sigAlgsToCertTypes ctx validAs
        Nothing -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    -- Unused:
    -- caAlgs <- extalgs caextID uncertsig
    -- (fork) Whether to compress OUR client certificate (RFC 8879).  This is
    -- driven by the @compress_certificate@ extension in the server's
    -- CertificateRequest, which is a separate direction from the extension we
    -- send in ClientHello (that one only governs the server's certificate).
    --
    -- We additionally require that we advertised support ourselves: a client
    -- that omitted @compress_certificate@ from its ClientHello has no business
    -- emitting a CompressedCertificate message.  'supportedLegacyClientHello'
    -- drops that extension (see 'Network.TLS.Handshake.Client.ClientHello'), so
    -- without this gate the legacy profile produces an inconsistent client:
    -- a tls-1.6.0-shaped ClientHello that nevertheless compresses its client
    -- certificate, which tls-1.6.0 could never do (it has no RFC 8879 support
    -- at all).  Peers that accepted the old client then reject the compressed
    -- Certificate and close with a bare FIN right after the handshake --
    -- surfacing to http-client as @NoResponseDataReceived@.
    let advertised = not $ supportedLegacyClientHello $ ctxSupported ctx
        zlib =
            advertised
                && lookupAndDecode
                    EID_CompressCertificate
                    MsgTCertificateRequest
                    exts
                    False
                    (\(CompressCertificate ccas) -> CCA_Zlib `elem` ccas)
    -- Everything the server told us it will accept.  If the client certificate
    -- is being rejected, the answer is usually visible by comparing our leaf's
    -- issuer (traced in 'sendClientFlight13') against @acceptableCAs@ here, or
    -- our CertificateVerify algorithm against @serverSigAlgs@.
    liftIO $
        tlsDebug $
            "processCertRequest13: CertReq ctxTokenLen="
                ++ show (B.length token)
                ++ " extIDs="
                ++ show [eid | ExtensionRaw eid _ <- exts]
                ++ " advertisedCompressCertificate="
                ++ show advertised
                ++ " clientCertCompression="
                ++ show zlib
                ++ " serverSigAlgs="
                ++ show hsAlgs
                ++ " derivedCertTypes="
                ++ show cTypes
                ++ " acceptableCAs(n="
                ++ show (length dNames)
                ++ ")="
                ++ show dNames
    usingHState ctx $ do
        setCertReqToken $ Just token
        setCertReqCBdata $ Just (cTypes, hsAlgs, dNames)
        setTLS13CertComp zlib
  where
    -- setCertReqSigAlgsCert caAlgs

    canames = case extensionLookup EID_CertificateAuthorities exts of
        Nothing -> return []
        Just ext -> case extensionDecode MsgTCertificateRequest ext of
            Just (CertificateAuthorities names) -> return names
            _ -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    extalgs extID decons = case extensionLookup extID exts of
        Nothing -> return Nothing
        Just ext -> case extensionDecode MsgTCertificateRequest ext of
            Just e ->
                return $ decons e
            _ -> throwCore $ Error_Protocol "invalid certificate request" HandshakeFailure
    unsighash
        :: SignatureAlgorithms
        -> Maybe [HashAndSignatureAlgorithm]
    unsighash (SignatureAlgorithms a) = Just a

----------------------------------------------------------------
-- not used in 0-RTT
expectCertAndVerify
    :: MonadIO m => ClientParams -> Context -> Handshake13 -> RecvHandshake13M m ()
expectCertAndVerify cparams ctx (Certificate13 _ (TLSCertificateChain cc) _) = processCertAndVerify cparams ctx cc
expectCertAndVerify cparams ctx (CompressedCertificate13 _ (TLSCertificateChain cc) _) = processCertAndVerify cparams ctx cc
expectCertAndVerify _ _ p = unexpected (show p) (Just "server certificate")

processCertAndVerify
    :: MonadIO m
    => ClientParams -> Context -> CertificateChain -> RecvHandshake13M m ()
processCertAndVerify cparams ctx cc = do
    liftIO $ usingState_ ctx $ setServerCertificateChain cc
    liftIO $ doCertificate cparams ctx cc
    let pubkey = certPubKey $ getCertificate $ getCertificateChainLeaf cc
    ver <- liftIO $ usingState_ ctx getVersion
    checkDigitalSignatureKey ver pubkey
    usingHState ctx $ setPublicKey pubkey
    recvHandshake13hash ctx $ expectCertVerify ctx pubkey

----------------------------------------------------------------

expectCertVerify
    :: MonadIO m => Context -> PubKey -> ByteString -> Handshake13 -> m ()
expectCertVerify ctx pubkey hChSc (CertVerify13 (DigitallySigned sigAlg sig)) = do
    ok <- checkCertVerify ctx pubkey sigAlg sig hChSc
    unless ok $ decryptError "cannot verify CertificateVerify"
expectCertVerify _ _ _ p = unexpected (show p) (Just "certificate verify")

----------------------------------------------------------------

expectFinished
    :: MonadIO m
    => ClientParams
    -> Context
    -> ByteString
    -> Handshake13
    -> m ()
expectFinished cparams ctx hashValue (Finished13 verifyData) = do
    st <- liftIO $ getTLS13State ctx
    let usedHash = cHash $ tls13stChoice st
        ServerTrafficSecret baseKey = triServer $ fromJust $ tls13stHsKey st
    checkFinished ctx usedHash baseKey hashValue verifyData
    liftIO $ do
        minfo <- contextGetInformation ctx
        case minfo of
            Nothing -> return ()
            Just info -> onServerFinished (clientHooks cparams) info
    liftIO $ modifyTLS13State ctx $ \s -> s{tls13stRecvSF = True}
expectFinished _ _ _ p = unexpected (show p) (Just "server finished")

----------------------------------------------------------------
----------------------------------------------------------------

sendClientSecondFlight13 :: ClientParams -> Context -> IO ()
sendClientSecondFlight13 cparams ctx = do
    st <- getTLS13State ctx
    let choice = tls13stChoice st
        hkey = fromJust $ tls13stHsKey st
        rtt0accepted = tls13st0RTTAccepted st
        eexts = tls13stClientExtensions st
    sendClientSecondFlight13' cparams ctx choice hkey rtt0accepted eexts
    modifyTLS13State ctx $ \s -> s{tls13stSentCF = True}

sendClientSecondFlight13'
    :: ClientParams
    -> Context
    -> CipherChoice
    -> SecretTriple HandshakeSecret
    -> Bool
    -> [ExtensionRaw]
    -> IO ()
sendClientSecondFlight13' cparams ctx choice hkey rtt0accepted eexts = do
    hChSf <- transcriptHash ctx
    unless (ctxQUICMode ctx) $
        runPacketFlight ctx $
            sendChangeCipherSpec13 ctx
    when (rtt0accepted && not (ctxQUICMode ctx)) $
        sendPacket13 ctx (Handshake13 [EndOfEarlyData13])
    let clientHandshakeSecret = triClient hkey
    setTxRecordState ctx usedHash usedCipher clientHandshakeSecret
    sendClientFlight13 cparams ctx usedHash clientHandshakeSecret
    appKey <- switchToApplicationSecret hChSf
    let applicationSecret = triBase appKey
    setResumptionSecret applicationSecret
    let appSecInfo = ApplicationSecretInfo (triClient appKey, triServer appKey)
    contextSync ctx $ SendClientFinished eexts appSecInfo
    modifyTLS13State ctx $ \st -> st{tls13stHsKey = Nothing}
    handshakeDone13 ctx
    rtt0 <- tls13st0RTT <$> getTLS13State ctx
    when rtt0 $ do
        builder <- tls13stPendingSentData <$> getTLS13State ctx
        modifyTLS13State ctx $ \st -> st{tls13stPendingSentData = id}
        unless rtt0accepted $
            mapM_ (sendPacket13 ctx . AppData13) $
                builder []
  where
    usedCipher = cCipher choice
    usedHash = cHash choice

    switchToApplicationSecret hChSf = do
        ensureRecvComplete ctx
        let handshakeSecret = triBase hkey
        appKey <- calculateApplicationSecret ctx choice handshakeSecret hChSf
        let serverApplicationSecret0 = triServer appKey
        let clientApplicationSecret0 = triClient appKey
        setTxRecordState ctx usedHash usedCipher clientApplicationSecret0
        setRxRecordState ctx usedHash usedCipher serverApplicationSecret0
        return appKey

    setResumptionSecret applicationSecret = do
        resumptionSecret <- calculateResumptionSecret ctx choice applicationSecret
        usingHState ctx $ setTLS13ResumptionSecret resumptionSecret

{- Unused for now
uncertsig :: SignatureAlgorithmsCert
          -> Maybe [HashAndSignatureAlgorithm]
uncertsig (SignatureAlgorithmsCert a) = Just a
-}

-- | (fork) Decide, rather than describe, whether our leaf certificate's issuer
-- is one the server said it would accept.
--
-- The three renderings this replaces (@show dNames@ in 'processCertRequest13',
-- @show certIssuerDN@ in 'describeCertChain', and the peer's own list) are not
-- comparable by eye: 'Show' on a 'DistinguishedName' hides the ASN.1 string
-- type and normalises nothing, so a DN encoded as @UTF8String@ and the same DN
-- encoded as @PrintableString@ print identically but are different bytes, and a
-- server matching @certificate_authorities@ compares bytes.  So compare the DER
-- encodings and report the verdict.
--
-- @leafIssuerInAcceptableCAs=False@ with a non-empty list is very likely the
-- whole answer: the peer cannot build a path from our certificate to a CA it
-- trusts, and TLS 1.3 gives it no way to say so during the handshake -- it
-- completes the handshake, then drops the connection.
--
-- An empty list is not a failure: @certificate_authorities@ is optional, and
-- when it is absent the server has told us nothing to violate.
acceptableCAVerdict
    :: Maybe CertificateChain
    -> Maybe
        ( [CertificateType]
        , Maybe [HashAndSignatureAlgorithm]
        , [DistinguishedName]
        )
    -> String
acceptableCAVerdict mcc mcbdata =
    "sendClientFlight13: acceptableCAs check:"
        ++ leafPart
        ++ " nAcceptableCAs="
        ++ show (length dNames)
        ++ " acceptableCA_DER_SHA256s=["
        ++ intercalate "," (map (hexOf . sha256 . encodeDNDER) dNames)
        ++ "]"
        ++ if null dNames
            then " (server advertised no certificate_authorities: no constraint)"
            else ""
  where
    sha256 = hash SHA256
    dNames = case mcbdata of
        Just (_, _, dns) -> dns
        Nothing -> []
    leafPart = case mcc of
        Just (CertificateChain (leaf : _)) ->
            let issuerDER = encodeDNDER $ certIssuerDN $ getCertificate leaf
                midx = elemIndex issuerDER $ map encodeDNDER dNames
             in " leafIssuerInAcceptableCAs="
                    ++ show (isJust midx)
                    ++ " matchIndex="
                    ++ show (fromMaybe (-1 :: Int) midx)
                    ++ " leafIssuerDER_SHA256="
                    ++ hexOf (sha256 issuerDER)
        _ ->
            " leafIssuerInAcceptableCAs=n/a matchIndex=-1"
                ++ " leafIssuerDER_SHA256=<no client certificate to check>"

sendClientFlight13
    :: ClientParams -> Context -> Hash -> ClientTrafficSecret a -> IO ()
sendClientFlight13 cparams ctx usedHash (ClientTrafficSecret baseKey) = do
    mcc <- clientChain cparams ctx
    tlsDebug $
        "sendClientFlight13: clientCertificate="
            ++ maybe
                "<none: server sent no CertificateRequest>"
                describeCertChain
                mcc
    -- 'clientChain' has just read the same field, so this cannot fail where it
    -- would not already have failed.
    mcbdata <- usingHState ctx getCertReqCBdata
    tlsDebug $ acceptableCAVerdict mcc mcbdata
    runPacketFlight ctx $ do
        case mcc of
            Nothing -> return ()
            Just cc -> do
                reqtoken <- usingHState ctx getCertReqToken
                certComp <- usingHState ctx getTLS13CertComp
                loadClientData13 cc reqtoken certComp
        rawFinished <- makeFinished ctx usedHash baseKey
        loadPacket13 ctx $ Handshake13 [rawFinished]
    when (isJust mcc) $
        modifyTLS13State ctx $
            \st -> st{tls13stSentClientCert = True}
  where
    loadClientData13 chain (Just token) certComp = do
        let (CertificateChain certs) = chain
            certExts = replicate (length certs) []
            cHashSigs = filter isHashSignatureValid13 $ supportedHashSignatures $ ctxSupported ctx
        let certtag = if certComp then CompressedCertificate13 else Certificate13
        -- RFC 8879 encoding detail, so the compressed message can be checked
        -- without a decryptable capture: @rawLen@ is the @uncompressed_length@
        -- field the peer will use to size its output buffer, @zlibLen@ is the
        -- @compressed_certificate_message@ length, and CMF\/FLG are the two
        -- zlib (RFC 1950) header bytes -- 78 9c is the usual default-compression
        -- stream; a peer that expects raw deflate (RFC 1951) rather than zlib
        -- would choke on exactly these two bytes.  Computed with the encoder's
        -- own function, so the numbers cannot drift from the wire.
        let compInfo
                | certComp =
                    let (rawB, zB) = compressCertificate13 token chain certExts
                        rawLen = B.length rawB
                        zlibLen = B.length zB
                     in " rawLen="
                            ++ show rawLen
                            ++ " zlibLen="
                            ++ show zlibLen
                            ++ " ratio="
                            ++ show (fromIntegral zlibLen / fromIntegral (max 1 rawLen) :: Double)
                            ++ " zlibHdrCMF_FLG="
                            ++ hexOf (B.take 2 zB)
                | otherwise = ""
        -- Which of the two Certificate encodings actually goes on the wire.
        -- tls-1.6.0 had no RFC 8879 support and so could only ever send
        -- 'Certificate13'; a peer that accepted the old client but rejects this
        -- handshake is the signature of a CompressedCertificate it cannot read.
        liftIO $
            tlsDebug $
                "sendClientFlight13: sending "
                    ++ (if certComp then "CompressedCertificate13 (zlib, RFC 8879)" else "Certificate13 (uncompressed)")
                    ++ " nCerts="
                    ++ show (length certs)
                    ++ " reqCtxLen="
                    ++ show (B.length token)
                    ++ compInfo
        loadPacket13 ctx $
            Handshake13 [certtag token (TLSCertificateChain chain) certExts]
        case certs of
            [] -> do
                liftIO $
                    tlsDebug
                        "sendClientFlight13: chain is EMPTY -> no CertificateVerify sent; peer sees an unauthenticated client"
                return ()
            (leaf : _) -> do
                hChSc <- transcriptHash ctx
                pubKey <- getLocalPublicKey ctx
                sigAlg <-
                    liftIO $ getLocalHashSigAlg ctx signatureCompatible13 cHashSigs pubKey
                -- Compare this against @serverSigAlgs@ from processCertRequest13:
                -- a signature scheme the server did not offer is a silent reject.
                liftIO $
                    tlsDebug $
                        "sendClientFlight13: CertificateVerify sigAlg="
                            ++ show sigAlg
                            ++ " pubkey="
                            ++ pubkeyType pubKey
                            ++ " clientOfferedSigAlgs="
                            ++ show cHashSigs
                vfy <- makeCertVerify ctx pubKey sigAlg hChSc
                -- Prove locally whether the signature we are about to send is
                -- valid for our own key.  This is the one check that separates
                -- "our signing path is broken" from "the peer rejects a
                -- perfectly good signature on policy grounds".
                liftIO $ case vfy of
                    CertVerify13 (DigitallySigned _ sig) -> do
                        ok <- selfCheckCertVerify ctx pubKey sigAlg sig hChSc
                        tlsDebug $
                            "sendClientFlight13: CertificateVerify self-check="
                                ++ show ok
                                ++ (if ok then " (signature valid for our own public key -- but see offline-verify below, this check is NOT conclusive)" else " (INVALID LOCALLY -- signing path is broken, no peer can accept this)")
                        ----------------------------------------------------
                        -- (fork) Re-verify this signature with an INDEPENDENT
                        -- implementation.
                        --
                        -- The self-check above must not be read as exonerating
                        -- the crypto backend.  It verifies with the same crypton
                        -- code that produced the signature, over the same
                        -- locally computed transcript, and crypton's PSS
                        -- verifier RECOVERS the salt length from the encoded
                        -- message instead of requiring it to equal hLen.  So a
                        -- non-conformant salt length -- the single most
                        -- plausible crypton-vs-cryptonite difference, and the
                        -- leading hypothesis for this bug -- still prints
                        -- self-check=True here while every RFC 8446 conformant
                        -- peer (OpenSSL, BoringSSL, JSSE) rejects the
                        -- CertificateVerify.  RFC 8446 4.2.3 REQUIRES the RSASSA-PSS
                        -- salt length to equal the digest length.
                        --
                        -- Everything needed to settle that offline is on the
                        -- next line.  Nothing on it is secret: the transcript
                        -- hash, the signed blob, the signature and the public
                        -- key all went out on the wire, or are derived from
                        -- bytes that did.
                        --
                        --   printf '%s' <signedBlob>  | xxd -r -p > tbs.bin
                        --   printf '%s' <sig>         | xxd -r -p > sig.bin
                        --   printf '%s' <leafSPKI>    | xxd -r -p > pub.der
                        --   sha256sum tbs.bin      # == signedBlobSHA256
                        --   openssl pkey -pubin -inform DER -in pub.der -text -noout
                        --
                        -- RSASSA-PSS (sigAlg rsa_pss_rsae_sha256 => -sha256,
                        -- MGF1-SHA256).  Sweep the salt length, because that is
                        -- what we are hunting:
                        --
                        --   for s in -1 -2 32 48 64 0 20; do
                        --     echo -n "saltlen=$s: "
                        --     openssl dgst -sha256 \
                        --       -verify pub.der -signature sig.bin \
                        --       -sigopt rsa_padding_mode:pss \
                        --       -sigopt rsa_pss_saltlen:$s \
                        --       -sigopt rsa_mgf1_md:sha256 tbs.bin
                        --   done
                        --
                        -- -1 = "salt length equals digest length", i.e. exactly
                        -- what RFC 8446 requires and what a strict peer checks.
                        -- -2 = "auto-recover whatever salt length is there",
                        -- i.e. what our own verifier effectively does.
                        -- If -2 verifies and -1 does not, the salt length is
                        -- wrong and that is the bug.  Substitute -sha384 /
                        -- -sha512 and rsa_mgf1_md accordingly for the other
                        -- rsa_pss_rsae_* algorithms.
                        --
                        -- RSASSA-PKCS1-v1_5 (only legal pre-1.3; a TLS 1.3 peer
                        -- MUST reject it in CertificateVerify):
                        --   openssl dgst -sha256 -verify pub.der \
                        --     -signature sig.bin tbs.bin
                        --
                        -- ECDSA (ecdsa_secp256r1_sha256, DER-encoded r,s):
                        --   openssl dgst -sha256 -verify pub.der \
                        --     -signature sig.bin tbs.bin
                        --
                        -- Ed25519 / Ed448 (no prehash):
                        --   openssl pkeyutl -verify -pubin -inkey pub.der \
                        --     -rawin -in tbs.bin -sigfile sig.bin
                        --
                        -- To confirm pub.der really is our leaf's key:
                        --   openssl x509 -inform DER -in leaf.der -pubkey -noout \
                        --     | openssl pkey -pubin -outform DER | sha256sum
                        --   # == leafSPKI_SHA256; and sha256sum leaf.der ==
                        --   # leafDER_SHA256, which identifies the certificate
                        --   # itself among several the process may hold.
                        ----------------------------------------------------
                        let signedBlob = makeTarget clientContextString hChSc
                            sigParams = signatureParams pubKey sigAlg
                            leafSPKI = encodePubKeyDER pubKey
                            leafDER = encodeSignedObject leaf
                            sha256 = hash SHA256
                            pssNote = case sigParams of
                                RSAParams h RSApss ->
                                    " pssRequiredSaltLenBytes="
                                        ++ show (hashDigestSize h)
                                        ++ " pssMGF1="
                                        ++ hashName h
                                _ -> ""
                        tlsDebug $
                            "sendClientFlight13: CertificateVerify offline-verify:"
                                ++ " transcriptHashAlg="
                                ++ hashName usedHash
                                ++ " transcriptHashSize="
                                ++ show (hashDigestSize usedHash)
                                ++ " transcriptHashLen="
                                ++ show (B.length hChSc)
                                ++ " transcriptHash="
                                ++ hexOf hChSc
                                ++ " contextString="
                                ++ show clientContextString
                                ++ " signedBlobLen="
                                ++ show (B.length signedBlob)
                                ++ " signedBlobSHA256="
                                ++ hexOf (sha256 signedBlob)
                                ++ " signedBlob="
                                ++ hexOf signedBlob
                                ++ " sigAlg="
                                ++ show sigAlg
                                ++ " sigParams="
                                ++ show sigParams
                                ++ pssNote
                                ++ " sigLen="
                                ++ show (B.length sig)
                                ++ " sig="
                                ++ hexOf sig
                                ++ " pubKeyType="
                                ++ pubkeyType pubKey
                                ++ " pubKeyBits="
                                ++ show (pubkeySizeBits pubKey)
                                ++ " leafSPKI_SHA256="
                                ++ hexOf (sha256 leafSPKI)
                                ++ " leafSPKI="
                                ++ hexOf leafSPKI
                                ++ " leafDERLen="
                                ++ show (B.length leafDER)
                                ++ " leafDER_SHA256="
                                ++ hexOf (sha256 leafDER)
                    _ -> return ()
                loadPacket13 ctx $ Handshake13 [vfy]
    --
    loadClientData13 _ _ _ =
        throwCore $
            Error_Protocol "missing TLS 1.3 certificate request context token" InternalError

----------------------------------------------------------------
----------------------------------------------------------------

postHandshakeAuthClientWith :: ClientParams -> Context -> Handshake13 -> IO ()
postHandshakeAuthClientWith cparams ctx h@(CertRequest13 certReqCtx exts) =
    bracket (saveHState ctx) (restoreHState ctx) $ \_ -> do
        processHandshake13 ctx h
        processCertRequest13 ctx certReqCtx exts
        (usedHash, _, level, applicationSecretN) <- getTxRecordState ctx
        unless (level == CryptApplicationSecret) $
            throwCore $
                Error_Protocol
                    "unexpected post-handshake authentication request"
                    UnexpectedMessage
        sendClientFlight13
            cparams
            ctx
            usedHash
            (ClientTrafficSecret applicationSecretN)
postHandshakeAuthClientWith _ _ _ =
    throwCore $
        Error_Protocol
            "unexpected handshake message received in postHandshakeAuthClientWith"
            UnexpectedMessage

----------------------------------------------------------------
----------------------------------------------------------------

asyncServerHello13
    :: ClientParams -> Context -> Maybe Group -> Millisecond -> IO ()
asyncServerHello13 cparams ctx groupSent chSentTime = do
    setPendingRecvActions
        ctx
        [ PendingRecvAction True expectServerHello
        , PendingRecvAction True (expectEncryptedExtensions ctx)
        , PendingRecvActionHash True expectFinishedAndSet
        ]
  where
    expectServerHello sh = do
        setRTT ctx chSentTime
        processServerHello13 cparams ctx sh
        void $ prepareSecondFlight13 ctx groupSent
    expectFinishedAndSet h sf = do
        expectFinished cparams ctx h sf
        liftIO $
            writeIORef (ctxPendingSendAction ctx) $
                Just $
                    sendClientSecondFlight13 cparams
