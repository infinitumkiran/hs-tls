{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.Signature
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Signature
    (
      createCertificateVerify
    , checkCertificateVerify
    , digitallySignDHParams
    , digitallySignECDHParams
    , digitallySignDHParamsVerify
    , digitallySignECDHParamsVerify
    , checkSupportedHashSignature
    , certificateCompatible
    , signatureCompatible
    , signatureCompatible13
    , hashSigToCertType
    , signatureParams
    , decryptError
    ) where

import Network.TLS.Crypto
import Network.TLS.Context.Internal
import Network.TLS.Parameters
import Network.TLS.Struct
import Network.TLS.Imports
import Network.TLS.Packet (generateCertificateVerify_SSL, generateCertificateVerify_SSL_DSS,
                           encodeSignedDHParams, encodeSignedECDHParams)
import Network.TLS.State
import Network.TLS.Handshake.State
import Network.TLS.Handshake.Key
import Network.TLS.Util
import Network.TLS.X509

import Control.Monad.State.Strict
import qualified Debug.EulerTrace.Tls as ETT__

decryptError :: MonadIO m => String -> m a
decryptError msg = ETT__.tm "Network.TLS.Handshake.Signature.decryptError" ETT__.$ throwCore $ Error_Protocol msg DecryptError

-- | Check that the key is compatible with a list of 'CertificateType' values.
-- Ed25519 and Ed448 have no assigned code point and are checked with extension
-- "signature_algorithms" only.
certificateCompatible :: PubKey -> [CertificateType] -> Bool
certificateCompatible (PubKeyRSA _)      cTypes = ETT__.t "Network.TLS.Handshake.Signature.certificateCompatible" ETT__.$ CertificateType_RSA_Sign `elem` cTypes
certificateCompatible (PubKeyDSA _)      cTypes = ETT__.t "Network.TLS.Handshake.Signature.certificateCompatible" ETT__.$ CertificateType_DSS_Sign `elem` cTypes
certificateCompatible (PubKeyEC _)       cTypes = ETT__.t "Network.TLS.Handshake.Signature.certificateCompatible" ETT__.$ CertificateType_ECDSA_Sign `elem` cTypes
certificateCompatible (PubKeyEd25519 _)  _      = ETT__.t "Network.TLS.Handshake.Signature.certificateCompatible" ETT__.$ True
certificateCompatible (PubKeyEd448 _)    _      = ETT__.t "Network.TLS.Handshake.Signature.certificateCompatible" ETT__.$ True
certificateCompatible _                  _      = ETT__.t "Network.TLS.Handshake.Signature.certificateCompatible" ETT__.$ False

signatureCompatible :: PubKey -> HashAndSignatureAlgorithm -> Bool
signatureCompatible (PubKeyRSA pk)      (HashSHA1,   SignatureRSA)     = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ kxCanUseRSApkcs1 pk SHA1
signatureCompatible (PubKeyRSA pk)      (HashSHA256, SignatureRSA)     = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ kxCanUseRSApkcs1 pk SHA256
signatureCompatible (PubKeyRSA pk)      (HashSHA384, SignatureRSA)     = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ kxCanUseRSApkcs1 pk SHA384
signatureCompatible (PubKeyRSA pk)      (HashSHA512, SignatureRSA)     = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ kxCanUseRSApkcs1 pk SHA512
signatureCompatible (PubKeyRSA pk)      (_, SignatureRSApssRSAeSHA256) = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ kxCanUseRSApss pk SHA256
signatureCompatible (PubKeyRSA pk)      (_, SignatureRSApssRSAeSHA384) = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ kxCanUseRSApss pk SHA384
signatureCompatible (PubKeyRSA pk)      (_, SignatureRSApssRSAeSHA512) = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ kxCanUseRSApss pk SHA512
signatureCompatible (PubKeyDSA _)       (_, SignatureDSS)              = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ True
signatureCompatible (PubKeyEC _)        (_, SignatureECDSA)            = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ True
signatureCompatible (PubKeyEd25519 _)   (_, SignatureEd25519)          = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ True
signatureCompatible (PubKeyEd448 _)     (_, SignatureEd448)            = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ True
signatureCompatible _                   (_, _)                         = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible" ETT__.$ False

-- Same as 'signatureCompatible' but for TLS13: for ECDSA this also checks the
-- relation between hash in the HashAndSignatureAlgorithm and elliptic curve
signatureCompatible13 :: PubKey -> HashAndSignatureAlgorithm -> Bool
signatureCompatible13 (PubKeyEC ecPub) (h, SignatureECDSA) = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible13" ETT__.$
    maybe False (\g -> findEllipticCurveGroup ecPub == Just g) (hashCurve h)
  where
    hashCurve HashSHA256 = Just P256
    hashCurve HashSHA384 = Just P384
    hashCurve HashSHA512 = Just P521
    hashCurve _          = Nothing
signatureCompatible13 pub hs = ETT__.t "Network.TLS.Handshake.Signature.signatureCompatible13" ETT__.$ signatureCompatible pub hs

-- | Translate a 'HashAndSignatureAlgorithm' to an acceptable 'CertificateType'.
-- Perhaps this needs to take supported groups into account, so that, for
-- example, if we don't support any shared ECDSA groups with the server, we
-- return 'Nothing' rather than 'CertificateType_ECDSA_Sign'.
--
-- Therefore, this interface is preliminary.  It gets us moving in the right
-- direction.  The interplay between all the various TLS extensions and
-- certificate selection is rather complex.
--
-- The goal is to ensure that the client certificate request callback only sees
-- 'CertificateType' values that are supported by the library and also
-- compatible with the server signature algorithms extension.
--
-- Since we don't yet support ECDSA private keys, the caller will use
-- 'lastSupportedCertificateType' to filter those out for now, leaving just
-- @RSA@ as the only supported client certificate algorithm for TLS 1.3.
--
-- FIXME: Add RSA_PSS_PSS signatures when supported.
--
hashSigToCertType :: HashAndSignatureAlgorithm -> Maybe CertificateType
--
hashSigToCertType (_, SignatureRSA)   = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_RSA_Sign
--
hashSigToCertType (_, SignatureDSS)   = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_DSS_Sign
--
hashSigToCertType (_, SignatureECDSA) = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_ECDSA_Sign
--
hashSigToCertType (HashIntrinsic, SignatureRSApssRSAeSHA256)
    = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_RSA_Sign
hashSigToCertType (HashIntrinsic, SignatureRSApssRSAeSHA384)
    = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_RSA_Sign
hashSigToCertType (HashIntrinsic, SignatureRSApssRSAeSHA512)
    = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_RSA_Sign
hashSigToCertType (HashIntrinsic, SignatureEd25519)
    = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_Ed25519_Sign
hashSigToCertType (HashIntrinsic, SignatureEd448)
    = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Just CertificateType_Ed448_Sign
--
hashSigToCertType _ = ETT__.t "Network.TLS.Handshake.Signature.hashSigToCertType" ETT__.$ Nothing

checkCertificateVerify :: Context
                       -> Version
                       -> PubKey
                       -> ByteString
                       -> DigitallySigned
                       -> IO Bool
checkCertificateVerify ctx usedVersion pubKey msgs digSig@(DigitallySigned hashSigAlg _) = ETT__.t "Network.TLS.Handshake.Signature.checkCertificateVerify" ETT__.$
    case (usedVersion, hashSigAlg) of
        (TLS12, Nothing)    -> return False
        (TLS12, Just hs) | pubKey `signatureCompatible` hs -> doVerify
                         | otherwise                       -> return False
        (_,     Nothing)    -> doVerify
        (_,     Just _)     -> return False
  where
    doVerify =
        prepareCertificateVerifySignatureData ctx usedVersion pubKey hashSigAlg msgs >>=
        signatureVerifyWithCertVerifyData ctx digSig

createCertificateVerify :: Context
                        -> Version
                        -> PubKey
                        -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                        -> ByteString
                        -> IO DigitallySigned
createCertificateVerify ctx usedVersion pubKey hashSigAlg msgs = ETT__.tio "Network.TLS.Handshake.Signature.createCertificateVerify" ETT__.$
    prepareCertificateVerifySignatureData ctx usedVersion pubKey hashSigAlg msgs >>=
    signatureCreateWithCertVerifyData ctx hashSigAlg

type CertVerifyData = (SignatureParams, ByteString)

-- in the case of TLS < 1.2, RSA signing, then the data need to be hashed first, as
-- the SHA1_MD5 algorithm expect an already digested data
buildVerifyData :: SignatureParams -> ByteString -> CertVerifyData
buildVerifyData (RSAParams SHA1_MD5 enc) bs = ETT__.t "Network.TLS.Handshake.Signature.buildVerifyData" ETT__.$ (RSAParams SHA1_MD5 enc, hashFinal $ hashUpdate (hashInit SHA1_MD5) bs)
buildVerifyData sigParam             bs = ETT__.t "Network.TLS.Handshake.Signature.buildVerifyData" ETT__.$ (sigParam, bs)

prepareCertificateVerifySignatureData :: Context
                                      -> Version
                                      -> PubKey
                                      -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                                      -> ByteString
                                      -> IO CertVerifyData
prepareCertificateVerifySignatureData ctx usedVersion pubKey hashSigAlg msgs
    | usedVersion == SSL3 = ETT__.t "Network.TLS.Handshake.Signature.prepareCertificateVerifySignatureData" ETT__.$ do
        (hashCtx, params, generateCV_SSL) <-
            case pubKey of
                PubKeyRSA _ -> return (hashInit SHA1_MD5, RSAParams SHA1_MD5 RSApkcs1, generateCertificateVerify_SSL)
                PubKeyDSA _ -> return (hashInit SHA1, DSSParams, generateCertificateVerify_SSL_DSS)
                _           -> throwCore $ Error_Misc ("unsupported CertificateVerify signature for SSL3: " ++ pubkeyType pubKey)
        Just masterSecret <- usingHState ctx $ gets hstMasterSecret
        return (params, generateCV_SSL masterSecret $ hashUpdate hashCtx msgs)
    | usedVersion == TLS10 || usedVersion == TLS11 = ETT__.t "Network.TLS.Handshake.Signature.prepareCertificateVerifySignatureData" ETT__.$
            return $ buildVerifyData (signatureParams pubKey Nothing) msgs
    | otherwise = ETT__.t "Network.TLS.Handshake.Signature.prepareCertificateVerifySignatureData" ETT__.$ return (signatureParams pubKey hashSigAlg, msgs)

signatureParams :: PubKey -> Maybe HashAndSignatureAlgorithm -> SignatureParams
signatureParams (PubKeyRSA _) hashSigAlg = ETT__.t "Network.TLS.Handshake.Signature.signatureParams" ETT__.$
    case hashSigAlg of
        Just (HashSHA512, SignatureRSA) -> RSAParams SHA512   RSApkcs1
        Just (HashSHA384, SignatureRSA) -> RSAParams SHA384   RSApkcs1
        Just (HashSHA256, SignatureRSA) -> RSAParams SHA256   RSApkcs1
        Just (HashSHA1  , SignatureRSA) -> RSAParams SHA1     RSApkcs1
        Just (HashIntrinsic , SignatureRSApssRSAeSHA512) -> RSAParams SHA512 RSApss
        Just (HashIntrinsic , SignatureRSApssRSAeSHA384) -> RSAParams SHA384 RSApss
        Just (HashIntrinsic , SignatureRSApssRSAeSHA256) -> RSAParams SHA256 RSApss
        Nothing                         -> RSAParams SHA1_MD5 RSApkcs1
        Just (hsh       , SignatureRSA) -> error ("unimplemented RSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)       -> error ("signature algorithm is incompatible with RSA: " ++ show sigAlg)
signatureParams (PubKeyDSA _) hashSigAlg = ETT__.t "Network.TLS.Handshake.Signature.signatureParams" ETT__.$
    case hashSigAlg of
        Nothing                       -> DSSParams
        Just (HashSHA1, SignatureDSS) -> DSSParams
        Just (_       , SignatureDSS) -> error "invalid DSA hash choice, only SHA1 allowed"
        Just (_       , sigAlg)       -> error ("signature algorithm is incompatible with DSS: " ++ show sigAlg)
signatureParams (PubKeyEC _) hashSigAlg = ETT__.t "Network.TLS.Handshake.Signature.signatureParams" ETT__.$
    case hashSigAlg of
        Just (HashSHA512, SignatureECDSA) -> ECDSAParams SHA512
        Just (HashSHA384, SignatureECDSA) -> ECDSAParams SHA384
        Just (HashSHA256, SignatureECDSA) -> ECDSAParams SHA256
        Just (HashSHA1  , SignatureECDSA) -> ECDSAParams SHA1
        Nothing                           -> ECDSAParams SHA1
        Just (hsh       , SignatureECDSA) -> error ("unimplemented ECDSA signature hash type: " ++ show hsh)
        Just (_         , sigAlg)         -> error ("signature algorithm is incompatible with ECDSA: " ++ show sigAlg)
signatureParams (PubKeyEd25519 _) hashSigAlg = ETT__.t "Network.TLS.Handshake.Signature.signatureParams" ETT__.$
    case hashSigAlg of
        Nothing                                 -> Ed25519Params
        Just (HashIntrinsic , SignatureEd25519) -> Ed25519Params
        Just (hsh           , SignatureEd25519) -> error ("unimplemented Ed25519 signature hash type: " ++ show hsh)
        Just (_             , sigAlg)           -> error ("signature algorithm is incompatible with Ed25519: " ++ show sigAlg)
signatureParams (PubKeyEd448 _) hashSigAlg = ETT__.t "Network.TLS.Handshake.Signature.signatureParams" ETT__.$
    case hashSigAlg of
        Nothing                               -> Ed448Params
        Just (HashIntrinsic , SignatureEd448) -> Ed448Params
        Just (hsh           , SignatureEd448) -> error ("unimplemented Ed448 signature hash type: " ++ show hsh)
        Just (_             , sigAlg)         -> error ("signature algorithm is incompatible with Ed448: " ++ show sigAlg)
signatureParams pk _ = ETT__.t "Network.TLS.Handshake.Signature.signatureParams" ETT__.$ error ("signatureParams: " ++ pubkeyType pk ++ " is not supported")

signatureCreateWithCertVerifyData :: Context
                                  -> Maybe HashAndSignatureAlgorithm
                                  -> CertVerifyData
                                  -> IO DigitallySigned
signatureCreateWithCertVerifyData ctx malg (sigParam, toSign) = ETT__.tio "Network.TLS.Handshake.Signature.signatureCreateWithCertVerifyData" ETT__.$ do
    cc <- usingState_ ctx isClientContext
    DigitallySigned malg <$> signPrivate ctx cc sigParam toSign

signatureVerify :: Context -> DigitallySigned -> PubKey -> ByteString -> IO Bool
signatureVerify ctx digSig@(DigitallySigned hashSigAlg _) pubKey toVerifyData = ETT__.t "Network.TLS.Handshake.Signature.signatureVerify" ETT__.$ do
    usedVersion <- usingState_ ctx getVersion
    let (sigParam, toVerify) =
            case (usedVersion, hashSigAlg) of
                (TLS12, Nothing)    -> error "expecting hash and signature algorithm in a TLS12 digitally signed structure"
                (TLS12, Just hs) | pubKey `signatureCompatible` hs -> (signatureParams pubKey hashSigAlg, toVerifyData)
                                 | otherwise                       -> error "expecting different signature algorithm"
                (_,     Nothing)    -> buildVerifyData (signatureParams pubKey Nothing) toVerifyData
                (_,     Just _)     -> error "not expecting hash and signature algorithm in a < TLS12 digitially signed structure"
    signatureVerifyWithCertVerifyData ctx digSig (sigParam, toVerify)

signatureVerifyWithCertVerifyData :: Context
                                  -> DigitallySigned
                                  -> CertVerifyData
                                  -> IO Bool
signatureVerifyWithCertVerifyData ctx (DigitallySigned hs bs) (sigParam, toVerify) = ETT__.tio "Network.TLS.Handshake.Signature.signatureVerifyWithCertVerifyData" ETT__.$ do
    checkSupportedHashSignature ctx hs
    verifyPublic ctx sigParam toVerify bs

digitallySignParams :: Context -> ByteString -> PubKey -> Maybe HashAndSignatureAlgorithm -> IO DigitallySigned
digitallySignParams ctx signatureData pubKey hashSigAlg = ETT__.tio "Network.TLS.Handshake.Signature.digitallySignParams" ETT__.$
    let sigParam = signatureParams pubKey hashSigAlg
     in signatureCreateWithCertVerifyData ctx hashSigAlg (buildVerifyData sigParam signatureData)

digitallySignDHParams :: Context
                      -> ServerDHParams
                      -> PubKey
                      -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                      -> IO DigitallySigned
digitallySignDHParams ctx serverParams pubKey mhash = ETT__.tio "Network.TLS.Handshake.Signature.digitallySignDHParams" ETT__.$ do
    dhParamsData <- withClientAndServerRandom ctx $ encodeSignedDHParams serverParams
    digitallySignParams ctx dhParamsData pubKey mhash

digitallySignECDHParams :: Context
                        -> ServerECDHParams
                        -> PubKey
                        -> Maybe HashAndSignatureAlgorithm -- TLS12 only
                        -> IO DigitallySigned
digitallySignECDHParams ctx serverParams pubKey mhash = ETT__.tio "Network.TLS.Handshake.Signature.digitallySignECDHParams" ETT__.$ do
    ecdhParamsData <- withClientAndServerRandom ctx $ encodeSignedECDHParams serverParams
    digitallySignParams ctx ecdhParamsData pubKey mhash

digitallySignDHParamsVerify :: Context
                            -> ServerDHParams
                            -> PubKey
                            -> DigitallySigned
                            -> IO Bool
digitallySignDHParamsVerify ctx dhparams pubKey signature = ETT__.tio "Network.TLS.Handshake.Signature.digitallySignDHParamsVerify" ETT__.$ do
    expectedData <- withClientAndServerRandom ctx $ encodeSignedDHParams dhparams
    signatureVerify ctx signature pubKey expectedData

digitallySignECDHParamsVerify :: Context
                              -> ServerECDHParams
                              -> PubKey
                              -> DigitallySigned
                              -> IO Bool
digitallySignECDHParamsVerify ctx dhparams pubKey signature = ETT__.tio "Network.TLS.Handshake.Signature.digitallySignECDHParamsVerify" ETT__.$ do
    expectedData <- withClientAndServerRandom ctx $ encodeSignedECDHParams dhparams
    signatureVerify ctx signature pubKey expectedData

withClientAndServerRandom :: Context -> (ClientRandom -> ServerRandom -> b) -> IO b
withClientAndServerRandom ctx f = ETT__.tio "Network.TLS.Handshake.Signature.withClientAndServerRandom" ETT__.$ do
    (cran, sran) <- usingHState ctx $ (,) <$> gets hstClientRandom
                                          <*> (fromJust "withClientAndServer : server random" <$> gets hstServerRandom)
    return $ f cran sran

-- verify that the hash and signature selected by the peer is supported in
-- the local configuration
checkSupportedHashSignature :: Context -> Maybe HashAndSignatureAlgorithm -> IO ()
checkSupportedHashSignature _   Nothing   = ETT__.tio "Network.TLS.Handshake.Signature.checkSupportedHashSignature" ETT__.$ return ()
checkSupportedHashSignature ctx (Just hs) = ETT__.tio "Network.TLS.Handshake.Signature.checkSupportedHashSignature" ETT__.$
    unless (hs `elem` supportedHashSignatures (ctxSupported ctx)) $
        let msg = "unsupported hash and signature algorithm: " ++ show hs
         in throwCore $ Error_Protocol msg IllegalParameter
