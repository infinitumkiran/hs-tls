{-# LANGUAGE OverloadedStrings #-}

-- | Tests for the backward-compatibility feature: TLS 1.0 / 1.1 support and the
-- legacy CBC / RC4 / 3DES cipher suites restored behind
-- 'defaultSupportedBackwardCompat' / 'ciphersuite_backwardCompat'.
--
-- The end-to-end tests run a full handshake plus data exchange between a real
-- client 'Context' and a real server 'Context' over an in-memory channel (the
-- 'Run' harness) — the library's analogue of a "mock server" integration test.
module BackwardCompatSpec (spec) where

import Control.Monad (forM_, void)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.IORef (newIORef, readIORef, writeIORef)
import Data.Maybe (fromJust, isJust)
import Data.X509 (ExtKeyUsageFlag (..), PubKey (..))
import Network.TLS
import Network.TLS.Extra.Cipher
import Network.TLS.Internal
import qualified Network.TLS.Cipher as C
import Test.Hspec
import Test.QuickCheck (Gen, generate, vector)

import API (recvDataAssert)
import Arbitrary
import Run
import Session

spec :: Spec
spec = do
    describe "defaultSupportedBackwardCompat" structuralSpec
    describe "ciphersuite_backwardCompat" cipherListSpec
    describe "legacy bulk ciphers (round-trip)" bulkSpec
    describe "DigitallySigned wire format" digitallySignedSpec
    describe "legacy handshakes (in-memory client <-> server)" handshakeMatrixSpec
    describe "legacy client authentication" clientAuthSpec
    describe "TLS 1.0/1.1 negative cases" negativeSpec
    describe "backward-compat config end to end" forkConfigSpec
    describe "TLS 1.0/1.1 record layer (multi-record data)" recordLayerSpec
    describe "TLS 1.0/1.1 protocol features" featureSpec
    describe "TLS 1.0/1.1 version negotiation" versionNegotiationSpec
    describe "TLS 1.0/1.1 renegotiation" renegotiationSpec
    describe "regression: secure defaults still work" regressionSpec

----------------------------------------------------------------
-- The three regressed settings the fork restores.

structuralSpec :: Spec
structuralSpec = do
    let s = defaultSupportedBackwardCompat
    it "floors versions at TLS 1.0, TLS 1.0 last" $
        supportedVersions s `shouldBe` [TLS13, TLS12, TLS11, TLS10]
    it "allows (does not require) Extended Main Secret" $
        supportedExtendedMainSecret s `shouldBe` AllowEMS
    it "re-adds the legacy SHA1/DSA hash-signature" $
        ((HashSHA1, SignatureDSA) `elem` supportedHashSignatures s)
            `shouldBe` True
    it "uses the backward-compat cipher list" $
        supportedCiphers s `shouldBe` ciphersuite_backwardCompat
    it "leaves the modern default untouched" $ do
        supportedVersions defaultSupported `shouldBe` [TLS13, TLS12]
        supportedExtendedMainSecret defaultSupported `shouldBe` RequireEMS

----------------------------------------------------------------
-- The cipher list contains the legacy suites but the *secure* default does not.

cipherListSpec :: Spec
cipherListSpec = do
    it "is a superset of ciphersuite_default (AEAD suites still preferred)" $
        all (`elem` ciphersuite_backwardCompat) ciphersuite_default `shouldBe` True
    it "contains the restored RSA-kx / CBC / RC4 / 3DES suites" $
        all (`elem` ciphersuite_backwardCompat) legacyRSACiphers `shouldBe` True
    it "contains the restored signed (DHE/ECDHE) CBC suites" $
        all (`elem` ciphersuite_backwardCompat) legacySignedCiphers `shouldBe` True
    it "keeps the insecure legacy suites OUT of ciphersuite_default" $
        any (`elem` ciphersuite_default) (legacyRSACiphers ++ legacySignedCiphers)
            `shouldBe` False

legacyRSACiphers :: [Cipher]
legacyRSACiphers =
    [ cipher_AES128_SHA1
    , cipher_AES256_SHA1
    , cipher_AES128_SHA256
    , cipher_AES256_SHA256
    , cipher_RSA_3DES_EDE_CBC_SHA1
    , cipher_RC4_128_SHA1
    , cipher_RC4_128_MD5
    ]

legacySignedCiphers :: [Cipher]
legacySignedCiphers =
    [ cipher_DHE_RSA_AES128_SHA1
    , cipher_DHE_RSA_AES256_SHA1
    , cipher_ECDHE_RSA_AES128CBC_SHA
    , cipher_ECDHE_RSA_AES256CBC_SHA
    , cipher_ECDHE_ECDSA_AES128CBC_SHA
    ]

----------------------------------------------------------------
-- Low-level: the restored bulk primitives encrypt/decrypt round-trip.
-- (The handshakes below also exercise these, plus MAC and padding.)

bulkSpec :: Spec
bulkSpec =
    forM_ bulkCases $ \(name, cipher) ->
        it ("encrypt then decrypt is identity: " ++ name) $ do
            let bulk = C.cipherBulk cipher
            key <- generate (B.pack <$> vector (C.bulkKeySize bulk))
            iv <- generate (B.pack <$> vector (C.bulkIVSize bulk + C.bulkExplicitIV bulk))
            -- one block for block ciphers, 64 bytes for the stream cipher
            let n = if C.bulkBlockSize bulk == 0 then 64 else C.bulkBlockSize bulk
            pt <- generate (B.pack <$> vector n)
            case (C.bulkInit bulk C.BulkEncrypt key, C.bulkInit bulk C.BulkDecrypt key) of
                (C.BulkStateBlock enc, C.BulkStateBlock dec) -> do
                    let (ct, _) = enc iv pt
                        (pt', _) = dec iv ct
                    pt' `shouldBe` pt
                (C.BulkStateStream (C.BulkStream enc), C.BulkStateStream (C.BulkStream dec)) ->
                    (fst . dec . fst . enc) pt `shouldBe` pt
                _ -> expectationFailure "unexpected bulk state for a legacy cipher"
  where
    bulkCases =
        [ ("AES128-CBC", cipher_AES128_SHA1)
        , ("AES256-CBC", cipher_AES256_SHA1)
        , ("3DES-EDE-CBC", cipher_RSA_3DES_EDE_CBC_SHA1)
        , ("RC4 (with SHA1)", cipher_RC4_128_SHA1)
        , ("RC4 (with MD5)", cipher_RC4_128_MD5)
        ]

----------------------------------------------------------------
-- Tier B: the DigitallySigned structure has no algorithm field before TLS 1.2.

digitallySignedSpec :: Spec
digitallySignedSpec = do
    let sig = B.replicate 48 0x5a
    it "TLS 1.2 round-trips WITH the hash/signature algorithm" $
        roundTrip TLS12 (DigitallySigned (HashSHA256, SignatureRSA) sig)
    it "TLS 1.1 round-trips WITHOUT an algorithm (sentinel)" $
        roundTrip TLS11 (DigitallySigned nullHashAndSignature sig)
    it "TLS 1.0 round-trips WITHOUT an algorithm (sentinel)" $
        roundTrip TLS10 (DigitallySigned nullHashAndSignature sig)
    it "the pre-TLS-1.2 encoding is exactly 2 bytes shorter" $ do
        let e10 = encodeHandshake (CertVerify (DigitallySigned nullHashAndSignature sig))
            e12 = encodeHandshake (CertVerify (DigitallySigned (HashSHA256, SignatureRSA) sig))
        (B.length e12 - B.length e10) `shouldBe` 2
  where
    roundTrip ver ds =
        decodeCertVerify ver (encodeHandshake (CertVerify ds))
            `shouldBe` Right (CertVerify ds)
    decodeCertVerify ver b =
        verifyResult (decodeHandshake (cp ver)) (decodeHandshakeRecord b)
    cp ver =
        CurrentParams
            { cParamsVersion = ver
            , cParamsKeyXchgType = Just CipherKeyExchange_RSA
            }
    verifyResult fn result = case result of
        GotSuccess (ty, content) -> fn ty content
        GotSuccessRemaining _ _ -> error "unexpected remaining bytes"
        GotPartial _ -> error "unexpected partial decode"
        GotError e -> error ("decode error: " ++ show e)

----------------------------------------------------------------
-- End to end: every restored suite, at every TLS version it can negotiate.

-- (label, cipher, versions the suite can be negotiated at)
handshakeMatrix :: [(String, Cipher, [Version])]
handshakeMatrix =
    [ ("RSA AES128-CBC-SHA", cipher_AES128_SHA1, legacyVers)
    , ("RSA AES256-CBC-SHA", cipher_AES256_SHA1, legacyVers)
    , ("RSA 3DES-CBC-SHA", cipher_RSA_3DES_EDE_CBC_SHA1, legacyVers)
    , ("RSA RC4-SHA", cipher_RC4_128_SHA1, legacyVers)
    , ("RSA RC4-MD5", cipher_RC4_128_MD5, legacyVers)
    , ("RSA AES128-CBC-SHA256", cipher_AES128_SHA256, [TLS12])
    , ("DHE-RSA AES128-CBC-SHA", cipher_DHE_RSA_AES128_SHA1, legacyVers)
    , ("DHE-RSA AES256-CBC-SHA", cipher_DHE_RSA_AES256_SHA1, legacyVers)
    , ("DHE-RSA AES128-CBC-SHA256", cipher_DHE_RSA_AES128_SHA256, [TLS12])
    , ("ECDHE-RSA AES128-CBC-SHA", cipher_ECDHE_RSA_AES128CBC_SHA, legacyVers)
    , ("ECDHE-RSA AES256-CBC-SHA", cipher_ECDHE_RSA_AES256CBC_SHA, legacyVers)
    , ("ECDHE-ECDSA AES128-CBC-SHA", cipher_ECDHE_ECDSA_AES128CBC_SHA, legacyVers)
    , ("ECDHE-RSA AES128-CBC-SHA256", cipher_ECDHE_RSA_AES128CBC_SHA256, [TLS12])
    ]
  where
    legacyVers = [TLS10, TLS11, TLS12]

handshakeMatrixSpec :: Spec
handshakeMatrixSpec =
    forM_ handshakeMatrix $ \(label, cipher, vers) ->
        forM_ vers $ \ver ->
            it (label ++ " negotiates over " ++ show ver) $ do
                params <- legacyParams ver cipher
                runTLSPredicate params $
                    maybe False $ \i ->
                        infoVersion i == ver && infoCipher i == cipher

----------------------------------------------------------------
-- Tier B: client-certificate authentication over TLS 1.0/1.1 (exercises the
-- CertificateVerify signature path in addition to the signed ServerKeyExchange).

clientAuthSpec :: Spec
clientAuthSpec =
    forM_ [TLS10, TLS11, TLS12] $ \ver -> do
        it ("RSA client authentication over " ++ show ver) $
            generate (arbitraryRSACredentialWithUsage [KeyUsage_digitalSignature])
                >>= clientAuth ver
        it ("ECDSA client authentication over " ++ show ver) $
            generate ecdsaClientCredential >>= clientAuth ver

-- Run a mutual-auth handshake with the given client credential.  Exercises the
-- CertificateVerify signature path (RSA -> SHA1_MD5, ECDSA -> SHA1 for TLS<1.2).
clientAuth :: Version -> (CertificateChain, PrivKey) -> IO ()
clientAuth ver cred = do
    (cparams, sparams) <- legacyParams ver cipher_ECDHE_RSA_AES128CBC_SHA
    let cparams' =
            cparams
                { clientHooks =
                    (clientHooks cparams){onCertificateRequest = \_ -> return (Just cred)}
                }
        sparams' =
            sparams
                { serverWantClientCert = True
                , serverHooks =
                    (serverHooks sparams)
                        { onClientCertificate = \chain ->
                            return $
                                if chain == fst cred
                                    then CertificateUsageAccept
                                    else CertificateUsageReject (CertificateRejectOther "unexpected")
                        }
                }
    runTLSSimple (cparams', sparams')

-- Pick the ECDSA credential out of the one-of-each-type set.
ecdsaClientCredential :: Gen (CertificateChain, PrivKey)
ecdsaClientCredential = do
    creds <- arbitraryCredentialsOfEachType'
    case [c | c@(chain, _) <- creds, isEC (leafPublicKey chain)] of
        (c : _) -> return c
        [] -> error "ecdsaClientCredential: no EC credential generated"
  where
    isEC (Just (PubKeyEC _)) = True
    isEC _ = False

----------------------------------------------------------------
-- Failure paths must be clean TLS exceptions, not hangs or crashes.

negativeSpec :: Spec
negativeSpec = forM_ [TLS10, TLS11] $ \ver -> do
    it ("fails cleanly when no cipher is in common over " ++ show ver) $ do
        base <-
            generate $
                arbitraryPairParamsWithVersionsAndCiphers
                    ([ver], [ver])
                    ([cipher_AES128_SHA1], [cipher_RSA_3DES_EDE_CBC_SHA1]) -- disjoint
        let params = withLegacyGroups (setEMSMode (NoEMS, NoEMS) base)
        runTLSFailure params handshake handshake
    it ("rejects an unacceptable client certificate over " ++ show ver) $ do
        (cparams, sparams) <- legacyParams ver cipher_ECDHE_RSA_AES128CBC_SHA
        cred <- generate (arbitraryRSACredentialWithUsage [KeyUsage_digitalSignature])
        let cparams' =
                cparams
                    { clientHooks =
                        (clientHooks cparams){onCertificateRequest = \_ -> return (Just cred)}
                    }
            sparams' =
                sparams
                    { serverWantClientCert = True
                    , serverHooks =
                        (serverHooks sparams)
                            { onClientCertificate = \_ ->
                                return (CertificateUsageReject (CertificateRejectOther "always reject"))
                            }
                    }
        runTLSFailure (cparams', sparams') handshake handshake

----------------------------------------------------------------
-- The backward-compat Supported value as a whole (all versions + all ciphers)
-- successfully negotiates a legacy connection.

forkConfigSpec :: Spec
forkConfigSpec =
    forM_ [TLS10, TLS11, TLS12] $ \ver ->
        it ("ciphersuite_backwardCompat negotiates a suite over " ++ show ver) $ do
            (cparams, sparams) <-
                generate $
                    arbitraryPairParamsWithVersionsAndCiphers
                        ([ver], [ver])
                        (ciphersuite_backwardCompat, ciphersuite_backwardCompat)
            let params = withLegacyGroups (setEMSMode (NoEMS, NoEMS) (cparams, sparams))
            runTLSPredicate params $ maybe False ((== ver) . infoVersion)

----------------------------------------------------------------
-- Regression: changes to shared record/handshake/packet code must not break
-- the modern secure paths.

regressionSpec :: Spec
regressionSpec = do
    it "TLS 1.3 still handshakes with the secure default" $
        generate arbitraryPairParams13 >>= runTLSSimple
    it "TLS 1.2 still handshakes with the secure default" $
        generate arbitraryPairParams12 >>= runTLSSimple

----------------------------------------------------------------
-- Helpers

-- Build a client/server pair pinned to a single version and cipher, with EMS
-- disabled (to isolate the cipher/version/signature paths under test) and with
-- groups that support both ECDHE (P256) and DHE (FFDHE2048).
legacyParams :: Version -> Cipher -> IO (ClientParams, ServerParams)
legacyParams ver cipher = do
    base <-
        generate $
            arbitraryPairParamsWithVersionsAndCiphers ([ver], [ver]) ([cipher], [cipher])
    return $ withLegacyGroups (setEMSMode (NoEMS, NoEMS) base)

withLegacyGroups
    :: (ClientParams, ServerParams) -> (ClientParams, ServerParams)
withLegacyGroups (cparams, sparams) = (cparams', sparams')
  where
    groups = [P256, FFDHE2048]
    cparams' =
        cparams
            { clientSupported =
                (clientSupported cparams){supportedGroups = groups}
            }
    sparams' =
        sparams
            { serverSupported =
                (serverSupported sparams){supportedGroups = groups}
            }

----------------------------------------------------------------
-- Record layer: exercises MAC sequencing, CBC IV chaining across many records,
-- and (for TLS 1.0 CBC) the 1/n-1 empty-record BEAST mitigation.

recordLayerSpec :: Spec
recordLayerSpec = do
    forM_ [TLS10, TLS11] $ \ver ->
        forM_ dataCiphers $ \(name, cipher) ->
            it ("exchanges many messages over " ++ show ver ++ " / " ++ name) $
                multiMessage ver cipher
    forM_ [TLS10, TLS11] $ \ver ->
        it ("exchanges a large multi-record payload over " ++ show ver) $
            largePayload ver
  where
    dataCiphers =
        [ ("AES128-CBC", cipher_AES128_SHA1)
        , ("AES256-CBC", cipher_AES256_SHA1)
        , ("3DES-CBC", cipher_RSA_3DES_EDE_CBC_SHA1)
        , ("RC4", cipher_RC4_128_SHA1)
        ]

multiMessage :: Version -> Cipher -> IO ()
multiMessage ver cipher = do
    params <- legacyParams ver cipher
    runTLSSuccess params hsClient hsServer
  where
    msgs = ["legacy ping 1", "legacy ping 2", "legacy ping 3", "legacy ping 4"]
    hsClient ctx = do
        handshake ctx
        forM_ msgs $ \m -> sendData ctx (L.fromStrict m) >> recvDataAssert ctx m
    hsServer ctx = do
        handshake ctx
        forM_ msgs $ \m -> recvDataAssert ctx m >> sendData ctx (L.fromStrict m)

largePayload :: Version -> IO ()
largePayload ver = do
    params <- legacyParams ver cipher_AES128_SHA1
    runTLSSuccess params hsClient hsServer
  where
    payload = B.replicate 40000 0xAB -- ~3 records, echoed back
    hsClient ctx = do
        handshake ctx
        sendData ctx (L.fromStrict payload)
        got <- recvExact ctx (B.length payload)
        got `shouldBe` payload
    hsServer ctx = do
        handshake ctx
        got <- recvExact ctx (B.length payload)
        sendData ctx (L.fromStrict got)

-- recvData yields one record's worth at a time (and skips empty records), so
-- accumulate until the whole payload has arrived.
recvExact :: Context -> Int -> IO B.ByteString
recvExact ctx n = go B.empty
  where
    go acc
        | B.length acc >= n = return acc
        | otherwise = do
            chunk <- recvData ctx
            if B.null chunk then return acc else go (acc `B.append` chunk)

----------------------------------------------------------------
-- Protocol features that a legacy peer relies on.

featureSpec :: Spec
featureSpec = forM_ [TLS10, TLS11] $ \ver -> do
    it ("negotiates ALPN over " ++ show ver) $ alpnTest ver
    it ("conveys SNI over " ++ show ver) $ sniTest ver
    it ("negotiates Extended Main Secret over " ++ show ver) $ emsTest ver
    it ("provides a matching tls-unique channel binding over " ++ show ver) $
        tlsUniqueTest ver
    it ("resumes a session over " ++ show ver) $ resumptionTest ver

alpnTest :: Version -> IO ()
alpnTest ver = do
    (cparams, sparams) <- legacyParams ver cipher_AES128_SHA1
    let cparams' =
            cparams
                { clientHooks =
                    (clientHooks cparams)
                        { onSuggestALPN = return (Just ["h2", "http/1.1"])
                        }
                }
        sparams' =
            sparams
                { serverHooks =
                    (serverHooks sparams){onALPNClientSuggest = Just chooseALPN}
                }
    runTLSSuccess (cparams', sparams') hsCheck hsCheck
  where
    chooseALPN xs = return (if "h2" `elem` xs then "h2" else "http/1.1")
    hsCheck ctx = do
        handshake ctx
        proto <- getNegotiatedProtocol ctx
        proto `shouldBe` Just "h2"

sniTest :: Version -> IO ()
sniTest ver = do
    (cparams, sparams) <- legacyParams ver cipher_AES128_SHA1
    ref <- newIORef Nothing
    let cparams' = cparams{clientServerIdentification = (sniName, "")}
        sparams' =
            sparams
                { serverHooks =
                    (serverHooks sparams)
                        { onServerNameIndication = \msni ->
                            writeIORef ref (Just msni) >> return (Credentials [])
                        }
                }
    runTLSSuccess (cparams', sparams') hsCheck hsCheck
    received <- readIORef ref
    received `shouldBe` Just (Just sniName)
  where
    sniName = "legacy.example.com"
    hsCheck ctx = do
        handshake ctx
        msni <- getClientSNI ctx
        msni `shouldBe` Just sniName

emsTest :: Version -> IO ()
emsTest ver = do
    base <- legacyParams ver cipher_AES128_SHA1
    let params = setEMSMode (AllowEMS, AllowEMS) base
    runTLSPredicate params (maybe False infoExtendedMainSecret)

-- tls-unique (RFC 5929) must be present and identical on both peers.
tlsUniqueTest :: Version -> IO ()
tlsUniqueTest ver = do
    (cparams, sparams) <- legacyParams ver cipher_AES128_SHA1
    cRef <- newIORef Nothing
    sRef <- newIORef Nothing
    runTLSSuccess (cparams, sparams) (store cRef) (store sRef)
    cu <- readIORef cRef
    su <- readIORef sRef
    cu `shouldBe` su
    cu `shouldSatisfy` maybe False (not . B.null)
  where
    store ref ctx = handshake ctx >> getTLSUnique ctx >>= writeIORef ref

resumptionTest :: Version -> IO ()
resumptionTest ver = do
    sessionRefs <- twoSessionRefs
    base <- legacyParams ver cipher_AES128_SHA1
    let params = setPairParamsSessionManagers (twoSessionManagers sessionRefs) base
    runTLSSimple params
    sess <- readClientSessionRef sessionRefs
    sess `shouldSatisfy` isJust
    let params2 = setPairParamsSessionResuming (fromJust sess) params
    runTLSPredicate params2 (maybe False infoTLS12Resumption)

----------------------------------------------------------------
-- Version negotiation / downgrade with the legacy versions in play.

versionNegotiationSpec :: Spec
versionNegotiationSpec =
    forM_ negotiationCases $ \(cvers, svers, expected) ->
        it (show cvers ++ " vs " ++ show svers ++ " negotiates " ++ show expected) $ do
            base <-
                generate $
                    arbitraryPairParamsWithVersionsAndCiphers
                        (cvers, svers)
                        ([cipher_AES128_SHA1], [cipher_AES128_SHA1])
            let params = withLegacyGroups (setEMSMode (NoEMS, NoEMS) base)
            runTLSPredicate params (maybe False ((== expected) . infoVersion))
  where
    negotiationCases =
        [ ([TLS12, TLS11, TLS10], [TLS10], TLS10)
        , ([TLS12, TLS11, TLS10], [TLS11], TLS11)
        , ([TLS11, TLS10], [TLS12, TLS11, TLS10], TLS11)
        , ([TLS10], [TLS12, TLS11, TLS10], TLS10)
        ]

----------------------------------------------------------------
-- Client-initiated renegotiation must be refused when disabled (a DoS guard).

renegotiationSpec :: Spec
renegotiationSpec =
    forM_ [TLS10, TLS11] $ \ver ->
        it ("refuses client-initiated renegotiation when disabled over " ++ show ver) $ do
            (cparams, sparams) <- legacyParams ver cipher_AES128_SHA1
            let sparams' =
                    sparams
                        { serverSupported =
                            (serverSupported sparams)
                                { supportedClientInitiatedRenegotiation = False
                                }
                        }
            runTLSFailure
                (cparams, sparams')
                (\ctx -> handshake ctx >> handshake ctx)
                (\ctx -> handshake ctx >> void (recvData ctx))
