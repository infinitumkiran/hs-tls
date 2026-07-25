module Network.TLS.Crypto.DH
    (
    -- * DH types
      DHParams
    , DHPublic
    , DHPrivate
    , DHKey

    -- * DH methods
    , dhPublic
    , dhPrivate
    , dhParams
    , dhParamsGetP
    , dhParamsGetG
    , dhParamsGetBits
    , dhGenerateKeyPair
    , dhGetShared
    , dhValid
    , dhUnwrap
    , dhUnwrapPublic
    ) where

import qualified Crypto.PubKey.DH as DH
import           Crypto.Number.Basic (numBits)
import qualified Data.ByteArray as B
import           Network.TLS.RNG
import qualified Debug.EulerTrace.Tls as ETT__

type DHPublic   = DH.PublicNumber
type DHPrivate  = DH.PrivateNumber
type DHParams   = DH.Params
type DHKey      = DH.SharedKey

dhPublic :: Integer -> DHPublic
dhPublic = ETT__.t "Network.TLS.Crypto.DH.dhPublic" ETT__.$ DH.PublicNumber

dhPrivate :: Integer -> DHPrivate
dhPrivate = ETT__.t "Network.TLS.Crypto.DH.dhPrivate" ETT__.$ DH.PrivateNumber

dhParams :: Integer -> Integer -> DHParams
dhParams p g = ETT__.t "Network.TLS.Crypto.DH.dhParams" ETT__.$ DH.Params p g (numBits p)

dhGenerateKeyPair :: MonadRandom r => DHParams -> r (DHPrivate, DHPublic)
dhGenerateKeyPair params = ETT__.tm "Network.TLS.Crypto.DH.dhGenerateKeyPair" ETT__.$ do
    priv <- DH.generatePrivate params
    let pub        = DH.calculatePublic params priv
    return (priv, pub)

dhGetShared :: DHParams -> DHPrivate -> DHPublic -> DHKey
dhGetShared params priv pub = ETT__.t "Network.TLS.Crypto.DH.dhGetShared" ETT__.$
    stripLeadingZeros (DH.getShared params priv pub)
  where
    -- strips leading zeros from the result of DH.getShared, as required
    -- for DH(E) premaster secret in SSL/TLS before version 1.3.
    stripLeadingZeros (DH.SharedKey sb) = DH.SharedKey (snd $ B.span (== 0) sb)

-- Check that group element in not in the 2-element subgroup { 1, p - 1 }.
-- See RFC 7919 section 3 and NIST SP 56A rev 2 section 5.6.2.3.1.
-- This verification is enough when using a safe prime.
dhValid :: DHParams -> Integer -> Bool
dhValid (DH.Params p _ _) y = ETT__.t "Network.TLS.Crypto.DH.dhValid" ETT__.$ 1 < y && y < p - 1

dhUnwrap :: DHParams -> DHPublic -> [Integer]
dhUnwrap (DH.Params p g _) (DH.PublicNumber y) = ETT__.t "Network.TLS.Crypto.DH.dhUnwrap" ETT__.$ [p,g,y]

dhParamsGetP :: DHParams -> Integer
dhParamsGetP (DH.Params p _ _) = ETT__.t "Network.TLS.Crypto.DH.dhParamsGetP" ETT__.$ p

dhParamsGetG :: DHParams -> Integer
dhParamsGetG (DH.Params _ g _) = ETT__.t "Network.TLS.Crypto.DH.dhParamsGetG" ETT__.$ g

dhParamsGetBits :: DHParams -> Int
dhParamsGetBits (DH.Params _ _ b) = ETT__.t "Network.TLS.Crypto.DH.dhParamsGetBits" ETT__.$ b

dhUnwrapPublic :: DHPublic -> Integer
dhUnwrapPublic (DH.PublicNumber y) = ETT__.t "Network.TLS.Crypto.DH.dhUnwrapPublic" ETT__.$ y
