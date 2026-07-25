-- |
-- Module      : Network.TLS.X509
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- X509 helpers
--
module Network.TLS.X509
    ( CertificateChain(..)
    , Certificate(..)
    , SignedCertificate
    , getCertificate
    , isNullCertificateChain
    , getCertificateChainLeaf
    , CertificateRejectReason(..)
    , CertificateUsage(..)
    , CertificateStore
    , ValidationCache
    , exceptionValidationCache
    , validateDefault
    , FailedReason
    , ServiceID
    , wrapCertificateChecks
    , pubkeyType
    ) where

import Data.X509
import Data.X509.Validation
import Data.X509.CertificateStore
import qualified Debug.EulerTrace.Tls as ETT__

isNullCertificateChain :: CertificateChain -> Bool
isNullCertificateChain (CertificateChain l) = ETT__.t "Network.TLS.X509.isNullCertificateChain" ETT__.$ null l

getCertificateChainLeaf :: CertificateChain -> SignedExact Certificate
getCertificateChainLeaf (CertificateChain [])    = ETT__.t "Network.TLS.X509.getCertificateChainLeaf" ETT__.$ error "empty certificate chain"
getCertificateChainLeaf (CertificateChain (x:_)) = ETT__.t "Network.TLS.X509.getCertificateChainLeaf" ETT__.$ x

-- | Certificate and Chain rejection reason
data CertificateRejectReason =
          CertificateRejectExpired
        | CertificateRejectRevoked
        | CertificateRejectUnknownCA
        | CertificateRejectAbsent
        | CertificateRejectOther String
        deriving (Show,Eq)

-- | Certificate Usage callback possible returns values.
data CertificateUsage =
          CertificateUsageAccept                         -- ^ usage of certificate accepted
        | CertificateUsageReject CertificateRejectReason -- ^ usage of certificate rejected
        deriving (Show,Eq)

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = ETT__.t "Network.TLS.X509.wrapCertificateChecks" ETT__.$ CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l   = ETT__.t "Network.TLS.X509.wrapCertificateChecks" ETT__.$ CertificateUsageReject   CertificateRejectExpired
    | InFuture `elem` l  = ETT__.t "Network.TLS.X509.wrapCertificateChecks" ETT__.$ CertificateUsageReject   CertificateRejectExpired
    | UnknownCA `elem` l = ETT__.t "Network.TLS.X509.wrapCertificateChecks" ETT__.$ CertificateUsageReject   CertificateRejectUnknownCA
    | SelfSigned `elem` l = ETT__.t "Network.TLS.X509.wrapCertificateChecks" ETT__.$ CertificateUsageReject  CertificateRejectUnknownCA
    | EmptyChain `elem` l = ETT__.t "Network.TLS.X509.wrapCertificateChecks" ETT__.$ CertificateUsageReject  CertificateRejectAbsent
    | otherwise          = ETT__.t "Network.TLS.X509.wrapCertificateChecks" ETT__.$ CertificateUsageReject $ CertificateRejectOther (show l)

pubkeyType :: PubKey -> String
pubkeyType = ETT__.t "Network.TLS.X509.pubkeyType" ETT__.$ show . pubkeyToAlg
