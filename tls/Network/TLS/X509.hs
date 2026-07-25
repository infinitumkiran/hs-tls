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
    encodeSignedObject,
    encodePubKeyDER,
    encodeDNDER,
    DistinguishedName,
) where

import Data.ASN1.BinaryEncoding (DER (..))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.Types (ASN1Object, toASN1)
import Data.ByteString (ByteString)
import Data.List (intercalate)
import Data.X509
import Data.X509.CertificateStore
import Data.X509.Validation

-- | (fork) DER of any ASN.1 object, used to render a public key or a
-- distinguished name in the exact form that goes on the wire, so it can be
-- compared byte for byte against a capture or fed to @openssl@.
encodeASN1Object :: ASN1Object a => a -> ByteString
encodeASN1Object o = encodeASN1' DER (toASN1 o [])

-- | (fork) DER of a @SubjectPublicKeyInfo@.  This is exactly what
-- @openssl pkey -pubin -inform DER@ expects, so a signature can be re-verified
-- offline against the key from the trace alone.
encodePubKeyDER :: PubKey -> ByteString
encodePubKeyDER = encodeASN1Object

-- | (fork) DER of a 'DistinguishedName'.  DNs must be compared in this form:
-- the 'Show' instance of a DN is lossy and two renderings that look identical
-- can differ in string encoding (UTF8String vs PrintableString) or attribute
-- order, which is precisely the difference that decides whether a server can
-- match our issuer against its @certificate_authorities@ list.
encodeDNDER :: DistinguishedName -> ByteString
encodeDNDER = encodeASN1Object

-- | (fork) Most certificates 'describeCertChain' will render.  A real chain is
-- three or four deep; anything past this is a peer being awkward.
describeCertChainCap :: Int
describeCertChainCap = 12

-- | (fork) One-line diagnostic summary of a certificate chain, for tracing an
-- mTLS handshake.  Subject and issuer are rendered with 'show' on the raw
-- 'DistinguishedName', which is for human reading only: 'show' is lossy, so do
-- NOT eyeball an issuer here against the @certificate_authorities@ list a
-- server advertises in its CertificateRequest.  That comparison is done on DER
-- ('encodeDNDER') and reported as a verdict by @acceptableCAVerdict@ in
-- "Network.TLS.Handshake.Client.TLS13".
--
-- The empty case is called out explicitly: a client that declines a
-- CertificateRequest still sends a well-formed (but empty) Certificate message,
-- which looks like a successful handshake locally and is rejected by the peer.
-- Peer-controlled input: a chain is whatever the other end chose to send, so the
-- number of certificates rendered is capped ('describeCertChainCap') rather than
-- trusted.  The emitter caps the resulting line as well, but a renderer that can
-- be made to do unbounded work is a hazard in its own right.
describeCertChain :: CertificateChain -> String
describeCertChain (CertificateChain []) =
    "<EMPTY: no certificate in chain - peer will see this as 'no certificate supplied'>"
describeCertChain (CertificateChain cs) =
    "n="
        ++ show n
        ++ " "
        ++ intercalate " | " (zipWith describe [(0 :: Int) ..] (take describeCertChainCap cs))
        ++ (if n > describeCertChainCap then " | ...<" ++ show (n - describeCertChainCap) ++ " more certificates not shown>" else "")
  where
    n = length cs
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
