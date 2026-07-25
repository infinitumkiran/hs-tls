-- |
-- Module      : Network.TLS.Handshake.Certificate
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake.Certificate
    ( certificateRejected
    , badCertificate
    , rejectOnException
    , verifyLeafKeyUsage
    , extractCAname
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct
import Network.TLS.X509
import Control.Monad (unless)
import Control.Monad.State.Strict
import Control.Exception (SomeException)
import Data.X509 (ExtKeyUsage(..), ExtKeyUsageFlag, extensionGet)
import qualified Debug.EulerTrace.Tls as ETT__

-- on certificate reject, throw an exception with the proper protocol alert error.
certificateRejected :: MonadIO m => CertificateRejectReason -> m a
certificateRejected CertificateRejectRevoked = ETT__.tm "Network.TLS.Handshake.Certificate.certificateRejected" ETT__.$
    throwCore $ Error_Protocol "certificate is revoked" CertificateRevoked
certificateRejected CertificateRejectExpired = ETT__.tm "Network.TLS.Handshake.Certificate.certificateRejected" ETT__.$
    throwCore $ Error_Protocol "certificate has expired" CertificateExpired
certificateRejected CertificateRejectUnknownCA = ETT__.tm "Network.TLS.Handshake.Certificate.certificateRejected" ETT__.$
    throwCore $ Error_Protocol "certificate has unknown CA" UnknownCa
certificateRejected CertificateRejectAbsent = ETT__.tm "Network.TLS.Handshake.Certificate.certificateRejected" ETT__.$
    throwCore $ Error_Protocol "certificate is missing" CertificateRequired
certificateRejected (CertificateRejectOther s) = ETT__.tm "Network.TLS.Handshake.Certificate.certificateRejected" ETT__.$
    throwCore $ Error_Protocol ("certificate rejected: " ++ s) CertificateUnknown

badCertificate :: MonadIO m => String -> m a
badCertificate msg = ETT__.tm "Network.TLS.Handshake.Certificate.badCertificate" ETT__.$ throwCore $ Error_Protocol msg BadCertificate

rejectOnException :: SomeException -> IO CertificateUsage
rejectOnException e = ETT__.tio "Network.TLS.Handshake.Certificate.rejectOnException" ETT__.$ return $ CertificateUsageReject $ CertificateRejectOther $ show e

verifyLeafKeyUsage :: MonadIO m => [ExtKeyUsageFlag] -> CertificateChain -> m ()
verifyLeafKeyUsage _          (CertificateChain [])         = ETT__.tm "Network.TLS.Handshake.Certificate.verifyLeafKeyUsage" ETT__.$ return ()
verifyLeafKeyUsage validFlags (CertificateChain (signed:_)) = ETT__.tm "Network.TLS.Handshake.Certificate.verifyLeafKeyUsage" ETT__.$
    unless verified $ badCertificate $
        "certificate is not allowed for any of " ++ show validFlags
  where
    cert     = getCertificate signed
    verified =
        case extensionGet (certExtensions cert) of
            Nothing                          -> True -- unrestricted cert
            Just (ExtKeyUsage flags)         -> any (`elem` validFlags) flags

extractCAname :: SignedCertificate -> DistinguishedName
extractCAname cert = ETT__.t "Network.TLS.Handshake.Certificate.extractCAname" ETT__.$ certSubjectDN $ getCertificate cert
