-- | X509 helpers
module Network.TLS.X509 (
    CertificateChain (..),
    Certificate (..),
    SignedCertificate,
    getCertificate,
    isNullCertificateChain,
    getCertificateChainLeaf,
    CertificateRejectReason (..),
    CertificateUsage (..),
    CertificateStore,
    ValidationCache,
    defaultValidationCache,
    exceptionValidationCache,
    validateDefault,
    FailedReason,
    ServiceID,
    wrapCertificateChecks,
    pubkeyType,
    validateClientCertificate,
    describeCertChain,
) where

import Data.List (intercalate)
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation

-- | (fork) One-line diagnostic summary of a certificate chain, for tracing an
-- mTLS handshake.  Subject and issuer are rendered with 'show' on the raw
-- 'DistinguishedName' so that an issuer here is directly comparable, byte for
-- byte, against the @certificate_authorities@ list a server advertises in its
-- CertificateRequest -- the check that tells you whether a peer can build a
-- path to your client certificate at all.
--
-- The empty case is called out explicitly: a client that declines a
-- CertificateRequest still sends a well-formed (but empty) Certificate message,
-- which looks like a successful handshake locally and is rejected by the peer.
describeCertChain :: CertificateChain -> String
describeCertChain (CertificateChain []) =
    "<EMPTY: no certificate in chain - peer will see this as 'no certificate supplied'>"
describeCertChain (CertificateChain cs) =
    "n=" ++ show (length cs) ++ " " ++ intercalate " | " (zipWith describe [(0 :: Int) ..] cs)
  where
    describe i sc =
        let c = getCertificate sc
            (notBefore, notAfter) = certValidity c
         in "["
                ++ show i
                ++ "] subject="
                ++ show (certSubjectDN c)
                ++ " issuer="
                ++ show (certIssuerDN c)
                ++ " serial="
                ++ show (certSerial c)
                ++ " notBefore="
                ++ show notBefore
                ++ " notAfter="
                ++ show notAfter
                ++ " pubkey="
                ++ pubkeyType (certPubKey c)

isNullCertificateChain :: CertificateChain -> Bool
isNullCertificateChain (CertificateChain l) = null l

getCertificateChainLeaf :: CertificateChain -> SignedExact Certificate
getCertificateChainLeaf (CertificateChain []) = error "empty certificate chain"
getCertificateChainLeaf (CertificateChain (x : _)) = x

-- | Certificate and Chain rejection reason
data CertificateRejectReason
    = CertificateRejectExpired
    | CertificateRejectRevoked
    | CertificateRejectUnknownCA
    | CertificateRejectAbsent
    | CertificateRejectOther String
    deriving (Show, Eq)

-- | Certificate Usage callback possible returns values.
data CertificateUsage
    = -- | usage of certificate accepted
      CertificateUsageAccept
    | -- | usage of certificate rejected
      CertificateUsageReject CertificateRejectReason
    deriving (Show, Eq)

wrapCertificateChecks :: [FailedReason] -> CertificateUsage
wrapCertificateChecks [] = CertificateUsageAccept
wrapCertificateChecks l
    | Expired `elem` l = CertificateUsageReject CertificateRejectExpired
    | InFuture `elem` l = CertificateUsageReject CertificateRejectExpired
    | UnknownCA `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | SelfSigned `elem` l = CertificateUsageReject CertificateRejectUnknownCA
    | EmptyChain `elem` l = CertificateUsageReject CertificateRejectAbsent
    | otherwise = CertificateUsageReject $ CertificateRejectOther (show l)

pubkeyType :: PubKey -> String
pubkeyType = show . pubkeyToAlg

-- | A utility function for client authentication which can be used
-- `onClientCertificate`.
--
-- Since: 2.1.7
validateClientCertificate
    :: CertificateStore
    -> ValidationCache
    -> CertificateChain
    -> IO CertificateUsage
validateClientCertificate store cache cc =
    wrapCertificateChecks
        <$> validate
            HashSHA256
            defaultHooks
            defaultChecks{checkFQHN = False}
            store
            cache
            ("", mempty)
            cc
