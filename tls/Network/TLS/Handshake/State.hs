{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Handshake.State
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.State
    ( HandshakeState(..)
    , HandshakeDigest(..)
    , HandshakeMode13(..)
    , RTT0Status(..)
    , CertReqCBdata
    , HandshakeM
    , newEmptyHandshake
    , runHandshake
    -- * key accessors
    , setPublicKey
    , setPublicPrivateKeys
    , getLocalPublicPrivateKeys
    , getRemotePublicKey
    , setServerDHParams
    , getServerDHParams
    , setServerECDHParams
    , getServerECDHParams
    , setDHPrivate
    , getDHPrivate
    , setGroupPrivate
    , getGroupPrivate
    -- * cert accessors
    , setClientCertSent
    , getClientCertSent
    , setCertReqSent
    , getCertReqSent
    , setClientCertChain
    , getClientCertChain
    , setCertReqToken
    , getCertReqToken
    , setCertReqCBdata
    , getCertReqCBdata
    , setCertReqSigAlgsCert
    , getCertReqSigAlgsCert
    -- * digest accessors
    , addHandshakeMessage
    , updateHandshakeDigest
    , getHandshakeMessages
    , getHandshakeMessagesRev
    , getHandshakeDigest
    , foldHandshakeDigest
    -- * master secret
    , setMasterSecret
    , setMasterSecretFromPre
    -- * misc accessor
    , getPendingCipher
    , setServerHelloParameters
    , setExtendedMasterSec
    , getExtendedMasterSec
    , setNegotiatedGroup
    , getNegotiatedGroup
    , setTLS13HandshakeMode
    , getTLS13HandshakeMode
    , setTLS13RTT0Status
    , getTLS13RTT0Status
    , setTLS13EarlySecret
    , getTLS13EarlySecret
    , setTLS13ResumptionSecret
    , getTLS13ResumptionSecret
    , setCCS13Sent
    , getCCS13Sent
    ) where

import Network.TLS.Util
import Network.TLS.Struct
import Network.TLS.Record.State
import Network.TLS.Packet
import Network.TLS.Crypto
import Network.TLS.Cipher
import Network.TLS.Compression
import Network.TLS.Types
import Network.TLS.Imports
import Control.Monad.State.Strict
import Data.X509 (CertificateChain)
import Data.ByteArray (ByteArrayAccess)
import qualified Debug.EulerTrace.Tls as ETT__

data HandshakeKeyState = HandshakeKeyState
    { hksRemotePublicKey :: !(Maybe PubKey)
    , hksLocalPublicPrivateKeys :: !(Maybe (PubKey, PrivKey))
    } deriving (Show)

data HandshakeDigest = HandshakeMessages [ByteString]
                     | HandshakeDigestContext HashCtx
                     deriving (Show)

data HandshakeState = HandshakeState
    { hstClientVersion       :: !Version
    , hstClientRandom        :: !ClientRandom
    , hstServerRandom        :: !(Maybe ServerRandom)
    , hstMasterSecret        :: !(Maybe ByteString)
    , hstKeyState            :: !HandshakeKeyState
    , hstServerDHParams      :: !(Maybe ServerDHParams)
    , hstDHPrivate           :: !(Maybe DHPrivate)
    , hstServerECDHParams    :: !(Maybe ServerECDHParams)
    , hstGroupPrivate        :: !(Maybe GroupPrivate)
    , hstHandshakeDigest     :: !HandshakeDigest
    , hstHandshakeMessages   :: [ByteString]
    , hstCertReqToken        :: !(Maybe ByteString)
        -- ^ Set to Just-value when a TLS13 certificate request is received
    , hstCertReqCBdata       :: !(Maybe CertReqCBdata)
        -- ^ Set to Just-value when a certificate request is received
    , hstCertReqSigAlgsCert  :: !(Maybe [HashAndSignatureAlgorithm])
        -- ^ In TLS 1.3, these are separate from the certificate
        -- issuer signature algorithm hints in the callback data.
        -- In TLS 1.2 the same list is overloaded for both purposes.
        -- Not present in TLS 1.1 and earlier
    , hstClientCertSent      :: !Bool
        -- ^ Set to true when a client certificate chain was sent
    , hstCertReqSent         :: !Bool
        -- ^ Set to true when a certificate request was sent.  This applies
        -- only to requests sent during handshake (not post-handshake).
    , hstClientCertChain     :: !(Maybe CertificateChain)
    , hstPendingTxState      :: Maybe RecordState
    , hstPendingRxState      :: Maybe RecordState
    , hstPendingCipher       :: Maybe Cipher
    , hstPendingCompression  :: Compression
    , hstExtendedMasterSec   :: Bool
    , hstNegotiatedGroup     :: Maybe Group
    , hstTLS13HandshakeMode  :: HandshakeMode13
    , hstTLS13RTT0Status     :: !RTT0Status
    , hstTLS13EarlySecret    :: Maybe (BaseSecret EarlySecret)
    , hstTLS13ResumptionSecret :: Maybe (BaseSecret ResumptionSecret)
    , hstCCS13Sent           :: !Bool
    } deriving (Show)

{- | When we receive a CertificateRequest from a server, a just-in-time
   callback is issued to the application to obtain a suitable certificate.
   Somewhat unfortunately, the callback parameters don't abstract away the
   details of the TLS 1.2 Certificate Request message, which combines the
   legacy @certificate_types@ and new @supported_signature_algorithms@
   parameters is a rather subtle way.

   TLS 1.2 also (again unfortunately, in the opinion of the author of this
   comment) overloads the signature algorithms parameter to constrain not only
   the algorithms used in TLS, but also the algorithms used by issuing CAs in
   the X.509 chain.  Best practice is to NOT treat such that restriction as a
   MUST, but rather take it as merely a preference, when a choice exists.  If
   the best chain available does not match the provided signature algorithm
   list, go ahead and use it anyway, it will probably work, and the server may
   not even care about the issuer CAs at all, it may be doing DANE or have
   explicit mappings for the client's public key, ...

   The TLS 1.3 @CertificateRequest@ message, drops @certificate_types@ and no
   longer overloads @supported_signature_algorithms@ to cover X.509.  It also
   includes a new opaque context token that the client must echo back, which
   makes certain client authentication replay attacks more difficult.  We will
   store that context separately, it does not need to be presented in the user
   callback.  The certificate signature algorithms preferred by the peer are
   now in the separate @signature_algorithms_cert@ extension, but we cannot
   report these to the application callback without an API change.  The good
   news is that filtering the X.509 signature types is generally unnecessary,
   unwise and difficult.  So we just ignore this extension.

   As a result, the information we provide to the callback is no longer a
   verbatim copy of the certificate request payload.  In the case of TLS 1.3
   The 'CertificateType' list is synthetically generated from the server's
   @signature_algorithms@ extension, and the @signature_algorithms_certs@
   extension is ignored.

   Since the original TLS 1.2 'CertificateType' has no provision for the newer
   certificate types that have appeared in TLS 1.3 we're adding some synthetic
   values that have no equivalent values in the TLS 1.2 'CertificateType' as
   defined in the IANA
   <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-2
   TLS ClientCertificateType Identifiers> registry.  These values are inferred
   from the TLS 1.3 @signature_algorithms@ extension, and will allow clients to
   present Ed25519 and Ed448 certificates when these become supported.
-}
type CertReqCBdata =
     ( [CertificateType]
     , Maybe [HashAndSignatureAlgorithm]
     , [DistinguishedName] )

newtype HandshakeM a = HandshakeM { runHandshakeM :: State HandshakeState a }
    deriving (Functor, Applicative, Monad)

instance MonadState HandshakeState HandshakeM where
    put x = HandshakeM (put x)
    get   = HandshakeM get
    state f = HandshakeM (state f)

-- create a new empty handshake state
newEmptyHandshake :: Version -> ClientRandom -> HandshakeState
newEmptyHandshake ver crand = ETT__.t "Network.TLS.Handshake.State.newEmptyHandshake" ETT__.$ HandshakeState
    { hstClientVersion       = ver
    , hstClientRandom        = crand
    , hstServerRandom        = Nothing
    , hstMasterSecret        = Nothing
    , hstKeyState            = HandshakeKeyState Nothing Nothing
    , hstServerDHParams      = Nothing
    , hstDHPrivate           = Nothing
    , hstServerECDHParams    = Nothing
    , hstGroupPrivate        = Nothing
    , hstHandshakeDigest     = HandshakeMessages []
    , hstHandshakeMessages   = []
    , hstCertReqToken        = Nothing
    , hstCertReqCBdata       = Nothing
    , hstCertReqSigAlgsCert  = Nothing
    , hstClientCertSent      = False
    , hstCertReqSent         = False
    , hstClientCertChain     = Nothing
    , hstPendingTxState      = Nothing
    , hstPendingRxState      = Nothing
    , hstPendingCipher       = Nothing
    , hstPendingCompression  = nullCompression
    , hstExtendedMasterSec   = False
    , hstNegotiatedGroup     = Nothing
    , hstTLS13HandshakeMode  = FullHandshake
    , hstTLS13RTT0Status     = RTT0None
    , hstTLS13EarlySecret    = Nothing
    , hstTLS13ResumptionSecret = Nothing
    , hstCCS13Sent           = False
    }

runHandshake :: HandshakeState -> HandshakeM a -> (a, HandshakeState)
runHandshake hst f = ETT__.t "Network.TLS.Handshake.State.runHandshake" ETT__.$ runState (runHandshakeM f) hst

setPublicKey :: PubKey -> HandshakeM ()
setPublicKey pk = ETT__.tm "Network.TLS.Handshake.State.setPublicKey" ETT__.$ modify (\hst -> hst { hstKeyState = setPK (hstKeyState hst) })
  where setPK hks = hks { hksRemotePublicKey = Just pk }

setPublicPrivateKeys :: (PubKey, PrivKey) -> HandshakeM ()
setPublicPrivateKeys keys = ETT__.tm "Network.TLS.Handshake.State.setPublicPrivateKeys" ETT__.$ modify (\hst -> hst { hstKeyState = setKeys (hstKeyState hst) })
  where setKeys hks = hks { hksLocalPublicPrivateKeys = Just keys }

getRemotePublicKey :: HandshakeM PubKey
getRemotePublicKey = ETT__.tm "Network.TLS.Handshake.State.getRemotePublicKey" ETT__.$ fromJust "remote public key" <$> gets (hksRemotePublicKey . hstKeyState)

getLocalPublicPrivateKeys :: HandshakeM (PubKey, PrivKey)
getLocalPublicPrivateKeys = ETT__.tm "Network.TLS.Handshake.State.getLocalPublicPrivateKeys" ETT__.$ fromJust "local public/private key" <$> gets (hksLocalPublicPrivateKeys . hstKeyState)

setServerDHParams :: ServerDHParams -> HandshakeM ()
setServerDHParams shp = ETT__.tm "Network.TLS.Handshake.State.setServerDHParams" ETT__.$ modify (\hst -> hst { hstServerDHParams = Just shp })

getServerDHParams :: HandshakeM ServerDHParams
getServerDHParams = ETT__.tm "Network.TLS.Handshake.State.getServerDHParams" ETT__.$ fromJust "server DH params" <$> gets hstServerDHParams

setServerECDHParams :: ServerECDHParams -> HandshakeM ()
setServerECDHParams shp = ETT__.tm "Network.TLS.Handshake.State.setServerECDHParams" ETT__.$ modify (\hst -> hst { hstServerECDHParams = Just shp })

getServerECDHParams :: HandshakeM ServerECDHParams
getServerECDHParams = ETT__.tm "Network.TLS.Handshake.State.getServerECDHParams" ETT__.$ fromJust "server ECDH params" <$> gets hstServerECDHParams

setDHPrivate :: DHPrivate -> HandshakeM ()
setDHPrivate shp = ETT__.tm "Network.TLS.Handshake.State.setDHPrivate" ETT__.$ modify (\hst -> hst { hstDHPrivate = Just shp })

getDHPrivate :: HandshakeM DHPrivate
getDHPrivate = ETT__.tm "Network.TLS.Handshake.State.getDHPrivate" ETT__.$ fromJust "server DH private" <$> gets hstDHPrivate

getGroupPrivate :: HandshakeM GroupPrivate
getGroupPrivate = ETT__.tm "Network.TLS.Handshake.State.getGroupPrivate" ETT__.$ fromJust "server ECDH private" <$> gets hstGroupPrivate

setGroupPrivate :: GroupPrivate -> HandshakeM ()
setGroupPrivate shp = ETT__.tm "Network.TLS.Handshake.State.setGroupPrivate" ETT__.$ modify (\hst -> hst { hstGroupPrivate = Just shp })

setExtendedMasterSec :: Bool -> HandshakeM ()
setExtendedMasterSec b = ETT__.tm "Network.TLS.Handshake.State.setExtendedMasterSec" ETT__.$ modify (\hst -> hst { hstExtendedMasterSec = b })

getExtendedMasterSec :: HandshakeM Bool
getExtendedMasterSec = ETT__.tm "Network.TLS.Handshake.State.getExtendedMasterSec" ETT__.$ gets hstExtendedMasterSec

setNegotiatedGroup :: Group -> HandshakeM ()
setNegotiatedGroup g = ETT__.tm "Network.TLS.Handshake.State.setNegotiatedGroup" ETT__.$ modify (\hst -> hst { hstNegotiatedGroup = Just g })

getNegotiatedGroup :: HandshakeM (Maybe Group)
getNegotiatedGroup = ETT__.tm "Network.TLS.Handshake.State.getNegotiatedGroup" ETT__.$ gets hstNegotiatedGroup

-- | Type to show which handshake mode is used in TLS 1.3.
data HandshakeMode13 =
      -- | Full handshake is used.
      FullHandshake
      -- | Full handshake is used with hello retry request.
    | HelloRetryRequest
      -- | Server authentication is skipped.
    | PreSharedKey
      -- | Server authentication is skipped and early data is sent.
    | RTT0
    deriving (Show,Eq)

setTLS13HandshakeMode :: HandshakeMode13 -> HandshakeM ()
setTLS13HandshakeMode s = ETT__.tm "Network.TLS.Handshake.State.setTLS13HandshakeMode" ETT__.$ modify (\hst -> hst { hstTLS13HandshakeMode = s })

getTLS13HandshakeMode :: HandshakeM HandshakeMode13
getTLS13HandshakeMode = ETT__.tm "Network.TLS.Handshake.State.getTLS13HandshakeMode" ETT__.$ gets hstTLS13HandshakeMode

data RTT0Status = RTT0None
                | RTT0Sent
                | RTT0Accepted
                | RTT0Rejected
                deriving (Show,Eq)

setTLS13RTT0Status :: RTT0Status -> HandshakeM ()
setTLS13RTT0Status s = ETT__.tm "Network.TLS.Handshake.State.setTLS13RTT0Status" ETT__.$ modify (\hst -> hst { hstTLS13RTT0Status = s })

getTLS13RTT0Status :: HandshakeM RTT0Status
getTLS13RTT0Status = ETT__.tm "Network.TLS.Handshake.State.getTLS13RTT0Status" ETT__.$ gets hstTLS13RTT0Status

setTLS13EarlySecret :: BaseSecret EarlySecret -> HandshakeM ()
setTLS13EarlySecret secret = ETT__.tm "Network.TLS.Handshake.State.setTLS13EarlySecret" ETT__.$ modify (\hst -> hst { hstTLS13EarlySecret = Just secret })

getTLS13EarlySecret :: HandshakeM (Maybe (BaseSecret EarlySecret))
getTLS13EarlySecret = ETT__.tm "Network.TLS.Handshake.State.getTLS13EarlySecret" ETT__.$ gets hstTLS13EarlySecret

setTLS13ResumptionSecret :: BaseSecret ResumptionSecret -> HandshakeM ()
setTLS13ResumptionSecret secret = ETT__.tm "Network.TLS.Handshake.State.setTLS13ResumptionSecret" ETT__.$ modify (\hst -> hst { hstTLS13ResumptionSecret = Just secret })

getTLS13ResumptionSecret :: HandshakeM (Maybe (BaseSecret ResumptionSecret))
getTLS13ResumptionSecret = ETT__.tm "Network.TLS.Handshake.State.getTLS13ResumptionSecret" ETT__.$ gets hstTLS13ResumptionSecret

setCCS13Sent :: Bool -> HandshakeM ()
setCCS13Sent sent = ETT__.tm "Network.TLS.Handshake.State.setCCS13Sent" ETT__.$ modify (\hst -> hst { hstCCS13Sent = sent })

getCCS13Sent :: HandshakeM Bool
getCCS13Sent = ETT__.tm "Network.TLS.Handshake.State.getCCS13Sent" ETT__.$ gets hstCCS13Sent

setCertReqSent :: Bool -> HandshakeM ()
setCertReqSent b = ETT__.tm "Network.TLS.Handshake.State.setCertReqSent" ETT__.$ modify (\hst -> hst { hstCertReqSent = b })

getCertReqSent :: HandshakeM Bool
getCertReqSent = ETT__.tm "Network.TLS.Handshake.State.getCertReqSent" ETT__.$ gets hstCertReqSent

setClientCertSent :: Bool -> HandshakeM ()
setClientCertSent b = ETT__.tm "Network.TLS.Handshake.State.setClientCertSent" ETT__.$ modify (\hst -> hst { hstClientCertSent = b })

getClientCertSent :: HandshakeM Bool
getClientCertSent = ETT__.tm "Network.TLS.Handshake.State.getClientCertSent" ETT__.$ gets hstClientCertSent

setClientCertChain :: CertificateChain -> HandshakeM ()
setClientCertChain b = ETT__.tm "Network.TLS.Handshake.State.setClientCertChain" ETT__.$ modify (\hst -> hst { hstClientCertChain = Just b })

getClientCertChain :: HandshakeM (Maybe CertificateChain)
getClientCertChain = ETT__.tm "Network.TLS.Handshake.State.getClientCertChain" ETT__.$ gets hstClientCertChain

--
setCertReqToken :: Maybe ByteString -> HandshakeM ()
setCertReqToken token = ETT__.tm "Network.TLS.Handshake.State.setCertReqToken" ETT__.$ modify $ \hst -> hst { hstCertReqToken = token }

getCertReqToken :: HandshakeM (Maybe ByteString)
getCertReqToken = ETT__.tm "Network.TLS.Handshake.State.getCertReqToken" ETT__.$ gets hstCertReqToken

--
setCertReqCBdata :: Maybe CertReqCBdata -> HandshakeM ()
setCertReqCBdata d = ETT__.tm "Network.TLS.Handshake.State.setCertReqCBdata" ETT__.$ modify (\hst -> hst { hstCertReqCBdata = d })

getCertReqCBdata :: HandshakeM (Maybe CertReqCBdata)
getCertReqCBdata = ETT__.tm "Network.TLS.Handshake.State.getCertReqCBdata" ETT__.$ gets hstCertReqCBdata

-- Dead code, until we find some use for the extension
setCertReqSigAlgsCert :: Maybe [HashAndSignatureAlgorithm] -> HandshakeM ()
setCertReqSigAlgsCert as = ETT__.tm "Network.TLS.Handshake.State.setCertReqSigAlgsCert" ETT__.$ modify $ \hst -> hst { hstCertReqSigAlgsCert = as }

getCertReqSigAlgsCert :: HandshakeM (Maybe [HashAndSignatureAlgorithm])
getCertReqSigAlgsCert = ETT__.tm "Network.TLS.Handshake.State.getCertReqSigAlgsCert" ETT__.$ gets hstCertReqSigAlgsCert

--
getPendingCipher :: HandshakeM Cipher
getPendingCipher = ETT__.tm "Network.TLS.Handshake.State.getPendingCipher" ETT__.$ fromJust "pending cipher" <$> gets hstPendingCipher

addHandshakeMessage :: ByteString -> HandshakeM ()
addHandshakeMessage content = ETT__.tm "Network.TLS.Handshake.State.addHandshakeMessage" ETT__.$ modify $ \hs -> hs { hstHandshakeMessages = content : hstHandshakeMessages hs}

getHandshakeMessages :: HandshakeM [ByteString]
getHandshakeMessages = ETT__.tm "Network.TLS.Handshake.State.getHandshakeMessages" ETT__.$ gets (reverse . hstHandshakeMessages)

getHandshakeMessagesRev :: HandshakeM [ByteString]
getHandshakeMessagesRev = ETT__.tm "Network.TLS.Handshake.State.getHandshakeMessagesRev" ETT__.$ gets hstHandshakeMessages

updateHandshakeDigest :: ByteString -> HandshakeM ()
updateHandshakeDigest content = ETT__.tm "Network.TLS.Handshake.State.updateHandshakeDigest" ETT__.$ modify $ \hs -> hs
    { hstHandshakeDigest = case hstHandshakeDigest hs of
        HandshakeMessages bytes        -> HandshakeMessages (content:bytes)
        HandshakeDigestContext hashCtx -> HandshakeDigestContext $ hashUpdate hashCtx content }

-- | Compress the whole transcript with the specified function.  Function @f@
-- takes the handshake digest as input and returns an encoded handshake message
-- to replace the transcript with.
foldHandshakeDigest :: Hash -> (ByteString -> ByteString) -> HandshakeM ()
foldHandshakeDigest hashAlg f = ETT__.tm "Network.TLS.Handshake.State.foldHandshakeDigest" ETT__.$ modify $ \hs ->
    case hstHandshakeDigest hs of
        HandshakeMessages bytes ->
            let hashCtx  = foldl hashUpdate (hashInit hashAlg) $ reverse bytes
                !folded  = f (hashFinal hashCtx)
             in hs { hstHandshakeDigest   = HandshakeMessages [folded]
                   , hstHandshakeMessages = [folded]
                   }
        HandshakeDigestContext hashCtx ->
            let !folded  = f (hashFinal hashCtx)
                hashCtx' = hashUpdate (hashInit hashAlg) folded
             in hs { hstHandshakeDigest   = HandshakeDigestContext hashCtx'
                   , hstHandshakeMessages = [folded]
                   }

getSessionHash :: HandshakeM ByteString
getSessionHash = ETT__.tm "Network.TLS.Handshake.State.getSessionHash" ETT__.$ gets $ \hst ->
    case hstHandshakeDigest hst of
        HandshakeDigestContext hashCtx -> hashFinal hashCtx
        HandshakeMessages _ -> error "un-initialized session hash"

getHandshakeDigest :: Version -> Role -> HandshakeM ByteString
getHandshakeDigest ver role = ETT__.tm "Network.TLS.Handshake.State.getHandshakeDigest" ETT__.$ gets gen
  where gen hst = case hstHandshakeDigest hst of
                      HandshakeDigestContext hashCtx ->
                         let msecret = fromJust "master secret" $ hstMasterSecret hst
                             cipher  = fromJust "cipher" $ hstPendingCipher hst
                          in generateFinish ver cipher msecret hashCtx
                      HandshakeMessages _        ->
                         error "un-initialized handshake digest"
        generateFinish | role == ClientRole = generateClientFinished
                       | otherwise          = generateServerFinished

-- | Generate the master secret from the pre master secret.
setMasterSecretFromPre :: ByteArrayAccess preMaster
                       => Version   -- ^ chosen transmission version
                       -> Role      -- ^ the role (Client or Server) of the generating side
                       -> preMaster -- ^ the pre master secret
                       -> HandshakeM ByteString
setMasterSecretFromPre ver role premasterSecret = ETT__.tm "Network.TLS.Handshake.State.setMasterSecretFromPre" ETT__.$ do
    ems <- getExtendedMasterSec
    secret <- if ems then get >>= genExtendedSecret else genSecret <$> get
    setMasterSecret ver role secret
    return secret
  where genSecret hst =
            generateMasterSecret ver (fromJust "cipher" $ hstPendingCipher hst)
                                 premasterSecret
                                 (hstClientRandom hst)
                                 (fromJust "server random" $ hstServerRandom hst)
        genExtendedSecret hst =
            generateExtendedMasterSec ver (fromJust "cipher" $ hstPendingCipher hst)
                                      premasterSecret
                <$> getSessionHash

-- | Set master secret and as a side effect generate the key block
-- with all the right parameters, and setup the pending tx/rx state.
setMasterSecret :: Version -> Role -> ByteString -> HandshakeM ()
setMasterSecret ver role masterSecret = ETT__.tm "Network.TLS.Handshake.State.setMasterSecret" ETT__.$ modify $ \hst ->
    let (pendingTx, pendingRx) = computeKeyBlock hst masterSecret ver role
     in hst { hstMasterSecret   = Just masterSecret
            , hstPendingTxState = Just pendingTx
            , hstPendingRxState = Just pendingRx }

computeKeyBlock :: HandshakeState -> ByteString -> Version -> Role -> (RecordState, RecordState)
computeKeyBlock hst masterSecret ver cc = ETT__.t "Network.TLS.Handshake.State.computeKeyBlock" ETT__.$ (pendingTx, pendingRx)
  where cipher       = fromJust "cipher" $ hstPendingCipher hst
        keyblockSize = cipherKeyBlockSize cipher

        bulk         = cipherBulk cipher
        digestSize   = if hasMAC (bulkF bulk) then hashDigestSize (cipherHash cipher)
                                              else 0
        keySize      = bulkKeySize bulk
        ivSize       = bulkIVSize bulk
        kb           = generateKeyBlock ver cipher (hstClientRandom hst)
                                        (fromJust "server random" $ hstServerRandom hst)
                                        masterSecret keyblockSize

        (cMACSecret, sMACSecret, cWriteKey, sWriteKey, cWriteIV, sWriteIV) =
                    fromJust "p6" $ partition6 kb (digestSize, digestSize, keySize, keySize, ivSize, ivSize)

        cstClient = CryptState { cstKey        = bulkInit bulk (BulkEncrypt `orOnServer` BulkDecrypt) cWriteKey
                               , cstIV         = cWriteIV
                               , cstMacSecret  = cMACSecret }
        cstServer = CryptState { cstKey        = bulkInit bulk (BulkDecrypt `orOnServer` BulkEncrypt) sWriteKey
                               , cstIV         = sWriteIV
                               , cstMacSecret  = sMACSecret }
        msClient = MacState { msSequence = 0 }
        msServer = MacState { msSequence = 0 }

        pendingTx = RecordState
                  { stCryptState  = if cc == ClientRole then cstClient else cstServer
                  , stMacState    = if cc == ClientRole then msClient else msServer
                  , stCryptLevel  = CryptMasterSecret
                  , stCipher      = Just cipher
                  , stCompression = hstPendingCompression hst
                  }
        pendingRx = RecordState
                  { stCryptState  = if cc == ClientRole then cstServer else cstClient
                  , stMacState    = if cc == ClientRole then msServer else msClient
                  , stCryptLevel  = CryptMasterSecret
                  , stCipher      = Just cipher
                  , stCompression = hstPendingCompression hst
                  }

        orOnServer f g = if cc == ClientRole then f else g


setServerHelloParameters :: Version      -- ^ chosen version
                         -> ServerRandom
                         -> Cipher
                         -> Compression
                         -> HandshakeM ()
setServerHelloParameters ver sran cipher compression = ETT__.tm "Network.TLS.Handshake.State.setServerHelloParameters" ETT__.$ do
    modify $ \hst -> hst
                { hstServerRandom       = Just sran
                , hstPendingCipher      = Just cipher
                , hstPendingCompression = compression
                , hstHandshakeDigest    = updateDigest $ hstHandshakeDigest hst
                }
  where hashAlg = getHash ver cipher
        updateDigest (HandshakeMessages bytes)  = HandshakeDigestContext $ foldl hashUpdate (hashInit hashAlg) $ reverse bytes
        updateDigest (HandshakeDigestContext _) = error "cannot initialize digest with another digest"

-- The TLS12 Hash is cipher specific, and some TLS12 algorithms use SHA384
-- instead of the default SHA256.
getHash :: Version -> Cipher -> Hash
getHash ver ciph
    | ver < TLS12                              = ETT__.t "Network.TLS.Handshake.State.getHash" ETT__.$ SHA1_MD5
    | maybe True (< TLS12) (cipherMinVer ciph) = ETT__.t "Network.TLS.Handshake.State.getHash" ETT__.$ SHA256
    | otherwise                                = ETT__.t "Network.TLS.Handshake.State.getHash" ETT__.$ cipherHash ciph
