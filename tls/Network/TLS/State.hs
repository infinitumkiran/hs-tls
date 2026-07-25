{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
-- Module      : Network.TLS.State
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the State module contains calls related to state initialization/manipulation
-- which is use by the Receiving module and the Sending module.
--
module Network.TLS.State
    ( TLSState(..)
    , TLSSt
    , runTLSState
    , newTLSState
    , withTLSRNG
    , updateVerifiedData
    , finishHandshakeTypeMaterial
    , finishHandshakeMaterial
    , certVerifyHandshakeTypeMaterial
    , certVerifyHandshakeMaterial
    , setVersion
    , setVersionIfUnset
    , getVersion
    , getVersionWithDefault
    , setSecureRenegotiation
    , getSecureRenegotiation
    , setExtensionALPN
    , getExtensionALPN
    , setNegotiatedProtocol
    , getNegotiatedProtocol
    , setClientALPNSuggest
    , getClientALPNSuggest
    , setClientEcPointFormatSuggest
    , getClientEcPointFormatSuggest
    , getClientCertificateChain
    , setClientCertificateChain
    , setClientSNI
    , getClientSNI
    , getVerifiedData
    , setSession
    , getSession
    , isSessionResuming
    , isClientContext
    , setExporterMasterSecret
    , getExporterMasterSecret
    , setTLS13KeyShare
    , getTLS13KeyShare
    , setTLS13PreSharedKey
    , getTLS13PreSharedKey
    , setTLS13HRR
    , getTLS13HRR
    , setTLS13Cookie
    , getTLS13Cookie
    , setClientSupportsPHA
    , getClientSupportsPHA
    -- * random
    , genRandom
    , withRNG
    ) where

import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.RNG
import Network.TLS.Types (Role(..), HostName)
import Network.TLS.Wire (GetContinuation)
import Network.TLS.Extension
import qualified Data.ByteString as B
import Control.Monad.State.Strict
import Network.TLS.ErrT
import Crypto.Random
import Data.X509 (CertificateChain)
import qualified Debug.EulerTrace.Tls as ETT__

data TLSState = TLSState
    { stSession             :: Session
    , stSessionResuming     :: Bool
    , stSecureRenegotiation :: Bool  -- RFC 5746
    , stClientVerifiedData  :: ByteString -- RFC 5746
    , stServerVerifiedData  :: ByteString -- RFC 5746
    , stExtensionALPN       :: Bool  -- RFC 7301
    , stHandshakeRecordCont :: Maybe (GetContinuation (HandshakeType, ByteString))
    , stNegotiatedProtocol  :: Maybe B.ByteString -- ALPN protocol
    , stHandshakeRecordCont13 :: Maybe (GetContinuation (HandshakeType13, ByteString))
    , stClientALPNSuggest   :: Maybe [B.ByteString]
    , stClientGroupSuggest  :: Maybe [Group]
    , stClientEcPointFormatSuggest :: Maybe [EcPointFormat]
    , stClientCertificateChain :: Maybe CertificateChain
    , stClientSNI           :: Maybe HostName
    , stRandomGen           :: StateRNG
    , stVersion             :: Maybe Version
    , stClientContext       :: Role
    , stTLS13KeyShare       :: Maybe KeyShare
    , stTLS13PreSharedKey   :: Maybe PreSharedKey
    , stTLS13HRR            :: !Bool
    , stTLS13Cookie         :: Maybe Cookie
    , stExporterMasterSecret :: Maybe ByteString -- TLS 1.3
    , stClientSupportsPHA   :: !Bool -- Post-Handshake Authentication (TLS 1.3)
    }

newtype TLSSt a = TLSSt { runTLSSt :: ErrT TLSError (State TLSState) a }
    deriving (Monad, MonadError TLSError, Functor, Applicative)

instance MonadState TLSState TLSSt where
    put x = TLSSt (lift $ put x)
    get   = TLSSt (lift get)
    state f = TLSSt (lift $ state f)

runTLSState :: TLSSt a -> TLSState -> (Either TLSError a, TLSState)
runTLSState f st = ETT__.t "Network.TLS.State.runTLSState" ETT__.$ runState (runErrT (runTLSSt f)) st

newTLSState :: StateRNG -> Role -> TLSState
newTLSState rng clientContext = ETT__.t "Network.TLS.State.newTLSState" ETT__.$ TLSState
    { stSession             = Session Nothing
    , stSessionResuming     = False
    , stSecureRenegotiation = False
    , stClientVerifiedData  = B.empty
    , stServerVerifiedData  = B.empty
    , stExtensionALPN       = False
    , stHandshakeRecordCont = Nothing
    , stHandshakeRecordCont13 = Nothing
    , stNegotiatedProtocol  = Nothing
    , stClientALPNSuggest   = Nothing
    , stClientGroupSuggest  = Nothing
    , stClientEcPointFormatSuggest = Nothing
    , stClientCertificateChain = Nothing
    , stClientSNI           = Nothing
    , stRandomGen           = rng
    , stVersion             = Nothing
    , stClientContext       = clientContext
    , stTLS13KeyShare       = Nothing
    , stTLS13PreSharedKey   = Nothing
    , stTLS13HRR            = False
    , stTLS13Cookie         = Nothing
    , stExporterMasterSecret = Nothing
    , stClientSupportsPHA   = False
    }

updateVerifiedData :: Role -> ByteString -> TLSSt ()
updateVerifiedData sending bs = ETT__.tm "Network.TLS.State.updateVerifiedData" ETT__.$ do
    cc <- isClientContext
    if cc /= sending
        then modify (\st -> st { stServerVerifiedData = bs })
        else modify (\st -> st { stClientVerifiedData = bs })

finishHandshakeTypeMaterial :: HandshakeType -> Bool
finishHandshakeTypeMaterial HandshakeType_ClientHello     = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_ServerHello     = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_Certificate     = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_HelloRequest    = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ False
finishHandshakeTypeMaterial HandshakeType_ServerHelloDone = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_ClientKeyXchg   = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_ServerKeyXchg   = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_CertRequest     = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_CertVerify      = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True
finishHandshakeTypeMaterial HandshakeType_Finished        = ETT__.t "Network.TLS.State.finishHandshakeTypeMaterial" ETT__.$ True

finishHandshakeMaterial :: Handshake -> Bool
finishHandshakeMaterial = ETT__.t "Network.TLS.State.finishHandshakeMaterial" ETT__.$ finishHandshakeTypeMaterial . typeOfHandshake

certVerifyHandshakeTypeMaterial :: HandshakeType -> Bool
certVerifyHandshakeTypeMaterial HandshakeType_ClientHello     = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ True
certVerifyHandshakeTypeMaterial HandshakeType_ServerHello     = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ True
certVerifyHandshakeTypeMaterial HandshakeType_Certificate     = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ True
certVerifyHandshakeTypeMaterial HandshakeType_HelloRequest    = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ False
certVerifyHandshakeTypeMaterial HandshakeType_ServerHelloDone = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ True
certVerifyHandshakeTypeMaterial HandshakeType_ClientKeyXchg   = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ True
certVerifyHandshakeTypeMaterial HandshakeType_ServerKeyXchg   = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ True
certVerifyHandshakeTypeMaterial HandshakeType_CertRequest     = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ True
certVerifyHandshakeTypeMaterial HandshakeType_CertVerify      = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ False
certVerifyHandshakeTypeMaterial HandshakeType_Finished        = ETT__.t "Network.TLS.State.certVerifyHandshakeTypeMaterial" ETT__.$ False

certVerifyHandshakeMaterial :: Handshake -> Bool
certVerifyHandshakeMaterial = ETT__.t "Network.TLS.State.certVerifyHandshakeMaterial" ETT__.$ certVerifyHandshakeTypeMaterial . typeOfHandshake

setSession :: Session -> Bool -> TLSSt ()
setSession session resuming = ETT__.tm "Network.TLS.State.setSession" ETT__.$ modify (\st -> st { stSession = session, stSessionResuming = resuming })

getSession :: TLSSt Session
getSession = ETT__.tm "Network.TLS.State.getSession" ETT__.$ gets stSession

isSessionResuming :: TLSSt Bool
isSessionResuming = ETT__.tm "Network.TLS.State.isSessionResuming" ETT__.$ gets stSessionResuming

setVersion :: Version -> TLSSt ()
setVersion ver = ETT__.tm "Network.TLS.State.setVersion" ETT__.$ modify (\st -> st { stVersion = Just ver })

setVersionIfUnset :: Version -> TLSSt ()
setVersionIfUnset ver = ETT__.tm "Network.TLS.State.setVersionIfUnset" ETT__.$ modify maybeSet
  where maybeSet st = case stVersion st of
                           Nothing -> st { stVersion = Just ver }
                           Just _  -> st

getVersion :: TLSSt Version
getVersion = ETT__.tm "Network.TLS.State.getVersion" ETT__.$ fromMaybe (error "internal error: version hasn't been set yet") <$> gets stVersion

getVersionWithDefault :: Version -> TLSSt Version
getVersionWithDefault defaultVer = ETT__.tm "Network.TLS.State.getVersionWithDefault" ETT__.$ fromMaybe defaultVer <$> gets stVersion

setSecureRenegotiation :: Bool -> TLSSt ()
setSecureRenegotiation b = ETT__.tm "Network.TLS.State.setSecureRenegotiation" ETT__.$ modify (\st -> st { stSecureRenegotiation = b })

getSecureRenegotiation :: TLSSt Bool
getSecureRenegotiation = ETT__.tm "Network.TLS.State.getSecureRenegotiation" ETT__.$ gets stSecureRenegotiation

setExtensionALPN :: Bool -> TLSSt ()
setExtensionALPN b = ETT__.tm "Network.TLS.State.setExtensionALPN" ETT__.$ modify (\st -> st { stExtensionALPN = b })

getExtensionALPN :: TLSSt Bool
getExtensionALPN = ETT__.tm "Network.TLS.State.getExtensionALPN" ETT__.$ gets stExtensionALPN

setNegotiatedProtocol :: B.ByteString -> TLSSt ()
setNegotiatedProtocol s = ETT__.tm "Network.TLS.State.setNegotiatedProtocol" ETT__.$ modify (\st -> st { stNegotiatedProtocol = Just s })

getNegotiatedProtocol :: TLSSt (Maybe B.ByteString)
getNegotiatedProtocol = ETT__.tm "Network.TLS.State.getNegotiatedProtocol" ETT__.$ gets stNegotiatedProtocol

setClientALPNSuggest :: [B.ByteString] -> TLSSt ()
setClientALPNSuggest ps = ETT__.tm "Network.TLS.State.setClientALPNSuggest" ETT__.$ modify (\st -> st { stClientALPNSuggest = Just ps})

getClientALPNSuggest :: TLSSt (Maybe [B.ByteString])
getClientALPNSuggest = ETT__.tm "Network.TLS.State.getClientALPNSuggest" ETT__.$ gets stClientALPNSuggest

setClientEcPointFormatSuggest :: [EcPointFormat] -> TLSSt ()
setClientEcPointFormatSuggest epf = ETT__.tm "Network.TLS.State.setClientEcPointFormatSuggest" ETT__.$ modify (\st -> st { stClientEcPointFormatSuggest = Just epf})

getClientEcPointFormatSuggest :: TLSSt (Maybe [EcPointFormat])
getClientEcPointFormatSuggest = ETT__.tm "Network.TLS.State.getClientEcPointFormatSuggest" ETT__.$ gets stClientEcPointFormatSuggest

setClientCertificateChain :: CertificateChain -> TLSSt ()
setClientCertificateChain s = ETT__.tm "Network.TLS.State.setClientCertificateChain" ETT__.$ modify (\st -> st { stClientCertificateChain = Just s })

getClientCertificateChain :: TLSSt (Maybe CertificateChain)
getClientCertificateChain = ETT__.tm "Network.TLS.State.getClientCertificateChain" ETT__.$ gets stClientCertificateChain

setClientSNI :: HostName -> TLSSt ()
setClientSNI hn = ETT__.tm "Network.TLS.State.setClientSNI" ETT__.$ modify (\st -> st { stClientSNI = Just hn })

getClientSNI :: TLSSt (Maybe HostName)
getClientSNI = ETT__.tm "Network.TLS.State.getClientSNI" ETT__.$ gets stClientSNI

getVerifiedData :: Role -> TLSSt ByteString
getVerifiedData client = ETT__.tm "Network.TLS.State.getVerifiedData" ETT__.$ gets (if client == ClientRole then stClientVerifiedData else stServerVerifiedData)

isClientContext :: TLSSt Role
isClientContext = ETT__.tm "Network.TLS.State.isClientContext" ETT__.$ gets stClientContext

genRandom :: Int -> TLSSt ByteString
genRandom n = ETT__.tm "Network.TLS.State.genRandom" ETT__.$ do
    withRNG (getRandomBytes n)

withRNG :: MonadPseudoRandom StateRNG a -> TLSSt a
withRNG f = ETT__.tm "Network.TLS.State.withRNG" ETT__.$ do
    st <- get
    let (a,rng') = withTLSRNG (stRandomGen st) f
    put (st { stRandomGen = rng' })
    return a

setExporterMasterSecret :: ByteString -> TLSSt ()
setExporterMasterSecret key = ETT__.tm "Network.TLS.State.setExporterMasterSecret" ETT__.$ modify (\st -> st { stExporterMasterSecret = Just key })

getExporterMasterSecret :: TLSSt (Maybe ByteString)
getExporterMasterSecret = ETT__.tm "Network.TLS.State.getExporterMasterSecret" ETT__.$ gets stExporterMasterSecret

setTLS13KeyShare :: Maybe KeyShare -> TLSSt ()
setTLS13KeyShare mks = ETT__.tm "Network.TLS.State.setTLS13KeyShare" ETT__.$ modify (\st -> st { stTLS13KeyShare = mks })

getTLS13KeyShare :: TLSSt (Maybe KeyShare)
getTLS13KeyShare = ETT__.tm "Network.TLS.State.getTLS13KeyShare" ETT__.$ gets stTLS13KeyShare

setTLS13PreSharedKey :: Maybe PreSharedKey -> TLSSt ()
setTLS13PreSharedKey mpsk = ETT__.tm "Network.TLS.State.setTLS13PreSharedKey" ETT__.$ modify (\st -> st { stTLS13PreSharedKey = mpsk })

getTLS13PreSharedKey :: TLSSt (Maybe PreSharedKey)
getTLS13PreSharedKey = ETT__.tm "Network.TLS.State.getTLS13PreSharedKey" ETT__.$ gets stTLS13PreSharedKey

setTLS13HRR :: Bool -> TLSSt ()
setTLS13HRR b = ETT__.tm "Network.TLS.State.setTLS13HRR" ETT__.$ modify (\st -> st { stTLS13HRR = b })

getTLS13HRR :: TLSSt Bool
getTLS13HRR = ETT__.tm "Network.TLS.State.getTLS13HRR" ETT__.$ gets stTLS13HRR

setTLS13Cookie :: Maybe Cookie -> TLSSt ()
setTLS13Cookie mcookie = ETT__.tm "Network.TLS.State.setTLS13Cookie" ETT__.$ modify (\st -> st { stTLS13Cookie = mcookie })

getTLS13Cookie :: TLSSt (Maybe Cookie)
getTLS13Cookie = ETT__.tm "Network.TLS.State.getTLS13Cookie" ETT__.$ gets stTLS13Cookie

setClientSupportsPHA :: Bool -> TLSSt ()
setClientSupportsPHA b = ETT__.tm "Network.TLS.State.setClientSupportsPHA" ETT__.$ modify (\st -> st { stClientSupportsPHA = b })

getClientSupportsPHA :: TLSSt Bool
getClientSupportsPHA = ETT__.tm "Network.TLS.State.getClientSupportsPHA" ETT__.$ gets stClientSupportsPHA
