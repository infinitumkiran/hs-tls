{-# LANGUAGE FlexibleInstances #-}
-- |
-- Module      : Network.TLS.Handshake.Key
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- functions for RSA operations
--
module Network.TLS.Handshake.Key
    ( encryptRSA
    , signPrivate
    , decryptRSA
    , verifyPublic
    , generateDHE
    , generateECDHE
    , generateECDHEShared
    , generateFFDHE
    , generateFFDHEShared
    , versionCompatible
    , isDigitalSignaturePair
    , checkDigitalSignatureKey
    , getLocalPublicKey
    , satisfiesEcPredicate
    , logKey
    ) where

import Control.Monad.State.Strict

import qualified Data.ByteString as B

import Network.TLS.Handshake.State
import Network.TLS.State (withRNG, getVersion)
import Network.TLS.Crypto
import Network.TLS.Types
import Network.TLS.Context.Internal
import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.X509
import qualified Debug.EulerTrace.Tls as ETT__

{- if the RSA encryption fails we just return an empty bytestring, and let the protocol
 - fail by itself; however it would be probably better to just report it since it's an internal problem.
 -}
encryptRSA :: Context -> ByteString -> IO ByteString
encryptRSA ctx content = ETT__.tio "Network.TLS.Handshake.Key.encryptRSA" ETT__.$ do
    publicKey <- usingHState ctx getRemotePublicKey
    usingState_ ctx $ do
        v <- withRNG $ kxEncrypt publicKey content
        case v of
            Left err       -> error ("rsa encrypt failed: " ++ show err)
            Right econtent -> return econtent

signPrivate :: Context -> Role -> SignatureParams -> ByteString -> IO ByteString
signPrivate ctx _ params content = ETT__.tio "Network.TLS.Handshake.Key.signPrivate" ETT__.$ do
    (publicKey, privateKey) <- usingHState ctx getLocalPublicPrivateKeys
    usingState_ ctx $ do
        r <- withRNG $ kxSign privateKey publicKey params content
        case r of
            Left err       -> error ("sign failed: " ++ show err)
            Right econtent -> return econtent

decryptRSA :: Context -> ByteString -> IO (Either KxError ByteString)
decryptRSA ctx econtent = ETT__.tio "Network.TLS.Handshake.Key.decryptRSA" ETT__.$ do
    (_, privateKey) <- usingHState ctx getLocalPublicPrivateKeys
    usingState_ ctx $ do
        ver <- getVersion
        let cipher = if ver < TLS10 then econtent else B.drop 2 econtent
        withRNG $ kxDecrypt privateKey cipher

verifyPublic :: Context -> SignatureParams -> ByteString -> ByteString -> IO Bool
verifyPublic ctx params econtent sign = ETT__.tio "Network.TLS.Handshake.Key.verifyPublic" ETT__.$ do
    publicKey <- usingHState ctx getRemotePublicKey
    return $ kxVerify publicKey params econtent sign

generateDHE :: Context -> DHParams -> IO (DHPrivate, DHPublic)
generateDHE ctx dhp = ETT__.tio "Network.TLS.Handshake.Key.generateDHE" ETT__.$ usingState_ ctx $ withRNG $ dhGenerateKeyPair dhp

generateECDHE :: Context -> Group -> IO (GroupPrivate, GroupPublic)
generateECDHE ctx grp = ETT__.tio "Network.TLS.Handshake.Key.generateECDHE" ETT__.$ usingState_ ctx $ withRNG $ groupGenerateKeyPair grp

generateECDHEShared :: Context -> GroupPublic -> IO (Maybe (GroupPublic, GroupKey))
generateECDHEShared ctx pub = ETT__.tio "Network.TLS.Handshake.Key.generateECDHEShared" ETT__.$ usingState_ ctx $ withRNG $ groupGetPubShared pub

generateFFDHE :: Context -> Group -> IO (DHParams, DHPrivate, DHPublic)
generateFFDHE ctx grp = ETT__.tio "Network.TLS.Handshake.Key.generateFFDHE" ETT__.$ usingState_ ctx $ withRNG $ dhGroupGenerateKeyPair grp

generateFFDHEShared :: Context -> Group -> DHPublic -> IO (Maybe (DHPublic, DHKey))
generateFFDHEShared ctx grp pub = ETT__.tio "Network.TLS.Handshake.Key.generateFFDHEShared" ETT__.$ usingState_ ctx $ withRNG $ dhGroupGetPubShared grp pub

isDigitalSignatureKey :: PubKey -> Bool
isDigitalSignatureKey (PubKeyRSA _)      = ETT__.t "Network.TLS.Handshake.Key.isDigitalSignatureKey" ETT__.$ True
isDigitalSignatureKey (PubKeyDSA _)      = ETT__.t "Network.TLS.Handshake.Key.isDigitalSignatureKey" ETT__.$ True
isDigitalSignatureKey (PubKeyEC  _)      = ETT__.t "Network.TLS.Handshake.Key.isDigitalSignatureKey" ETT__.$ True
isDigitalSignatureKey (PubKeyEd25519 _)  = ETT__.t "Network.TLS.Handshake.Key.isDigitalSignatureKey" ETT__.$ True
isDigitalSignatureKey (PubKeyEd448   _)  = ETT__.t "Network.TLS.Handshake.Key.isDigitalSignatureKey" ETT__.$ True
isDigitalSignatureKey _                  = ETT__.t "Network.TLS.Handshake.Key.isDigitalSignatureKey" ETT__.$ False

versionCompatible :: PubKey -> Version -> Bool
versionCompatible (PubKeyRSA _)       _ = ETT__.t "Network.TLS.Handshake.Key.versionCompatible" ETT__.$ True
versionCompatible (PubKeyDSA _)       v = ETT__.t "Network.TLS.Handshake.Key.versionCompatible" ETT__.$ v <= TLS12
versionCompatible (PubKeyEC _)        v = ETT__.t "Network.TLS.Handshake.Key.versionCompatible" ETT__.$ v >= TLS10
versionCompatible (PubKeyEd25519 _)   v = ETT__.t "Network.TLS.Handshake.Key.versionCompatible" ETT__.$ v >= TLS12
versionCompatible (PubKeyEd448 _)     v = ETT__.t "Network.TLS.Handshake.Key.versionCompatible" ETT__.$ v >= TLS12
versionCompatible _                   _ = ETT__.t "Network.TLS.Handshake.Key.versionCompatible" ETT__.$ False

-- | Test whether the argument is a public key supported for signature at the
-- specified TLS version.  This also accepts a key for RSA encryption.  This
-- test is performed by clients or servers before verifying a remote
-- Certificate Verify.
checkDigitalSignatureKey :: MonadIO m => Version -> PubKey -> m ()
checkDigitalSignatureKey usedVersion key = ETT__.tm "Network.TLS.Handshake.Key.checkDigitalSignatureKey" ETT__.$ do
    unless (isDigitalSignatureKey key) $
        throwCore $ Error_Protocol "unsupported remote public key type" HandshakeFailure
    unless (key `versionCompatible` usedVersion) $
        throwCore $ Error_Protocol (show usedVersion ++ " has no support for " ++ pubkeyType key) IllegalParameter

-- | Test whether the argument is matching key pair supported for signature.
-- This also accepts material for RSA encryption.  This test is performed by
-- servers or clients before using a credential from the local configuration.
isDigitalSignaturePair :: (PubKey, PrivKey) -> Bool
isDigitalSignaturePair keyPair = ETT__.t "Network.TLS.Handshake.Key.isDigitalSignaturePair" ETT__.$
    case keyPair of
        (PubKeyRSA      _, PrivKeyRSA      _)  -> True
        (PubKeyDSA      _, PrivKeyDSA      _)  -> True
        (PubKeyEC       _, PrivKeyEC       k)  -> kxSupportedPrivKeyEC k
        (PubKeyEd25519  _, PrivKeyEd25519  _)  -> True
        (PubKeyEd448    _, PrivKeyEd448    _)  -> True
        _                                      -> False

getLocalPublicKey :: MonadIO m => Context -> m PubKey
getLocalPublicKey ctx = ETT__.tm "Network.TLS.Handshake.Key.getLocalPublicKey" ETT__.$
    usingHState ctx (fst <$> getLocalPublicPrivateKeys)

-- | Test whether the public key satisfies a predicate about the elliptic curve.
-- When the public key is not suitable for ECDSA, like RSA for instance, the
-- predicate is not used and the result is 'True'.
satisfiesEcPredicate :: (Group -> Bool) -> PubKey -> Bool
satisfiesEcPredicate p (PubKeyEC ecPub) = ETT__.t "Network.TLS.Handshake.Key.satisfiesEcPredicate" ETT__.$
    maybe False p $ findEllipticCurveGroup ecPub
satisfiesEcPredicate _ _                = ETT__.t "Network.TLS.Handshake.Key.satisfiesEcPredicate" ETT__.$ True

----------------------------------------------------------------

class LogLabel a where
    labelAndKey :: a -> (String, ByteString)

instance LogLabel MasterSecret where
    labelAndKey (MasterSecret key) = ("CLIENT_RANDOM", key)

instance LogLabel (ClientTrafficSecret EarlySecret) where
    labelAndKey (ClientTrafficSecret key) = ("CLIENT_EARLY_TRAFFIC_SECRET", key)

instance LogLabel (ServerTrafficSecret HandshakeSecret) where
    labelAndKey (ServerTrafficSecret key) = ("SERVER_HANDSHAKE_TRAFFIC_SECRET", key)

instance LogLabel (ClientTrafficSecret HandshakeSecret) where
    labelAndKey (ClientTrafficSecret key) = ("CLIENT_HANDSHAKE_TRAFFIC_SECRET", key)

instance LogLabel (ServerTrafficSecret ApplicationSecret) where
    labelAndKey (ServerTrafficSecret key) = ("SERVER_TRAFFIC_SECRET_0", key)

instance LogLabel (ClientTrafficSecret ApplicationSecret) where
    labelAndKey (ClientTrafficSecret key) = ("CLIENT_TRAFFIC_SECRET_0", key)

-- NSS Key Log Format
-- See https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format
logKey :: LogLabel a => Context -> a -> IO ()
logKey ctx logkey = ETT__.tio "Network.TLS.Handshake.Key.logKey" ETT__.$ do
    mhst <- getHState ctx
    case mhst of
      Nothing  -> return ()
      Just hst -> do
          let cr = unClientRandom $ hstClientRandom hst
              (label,key) = labelAndKey logkey
          ctxKeyLogger ctx $ label ++ " " ++ dump cr ++ " " ++ dump key
  where
    dump = init . tail . showBytesHex
