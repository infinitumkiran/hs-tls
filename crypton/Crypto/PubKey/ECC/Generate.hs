-- | Signature generation.
module Crypto.PubKey.ECC.Generate where

import Crypto.Number.Generate
import Crypto.PubKey.ECC.ECDSA
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Types
import Crypto.Random.Types
import qualified Debug.EulerTrace.Crypton as ETT__

-- | Generate Q given d.
--
-- /WARNING:/ Vulnerable to timing attacks.
generateQ
    :: Curve
    -> Integer
    -> Point
generateQ curve d = ETT__.t "Crypto.PubKey.ECC.Generate.generateQ" ETT__.$ pointMul curve d g
  where
    g = ecc_g $ common_curve curve

-- | Generate a pair of (private, public) key.
--
-- /WARNING:/ Vulnerable to timing attacks.
generate
    :: MonadRandom m
    => Curve
    -- ^ Elliptic Curve
    -> m (PublicKey, PrivateKey)
generate curve = ETT__.tm "Crypto.PubKey.ECC.Generate.generate" ETT__.$ do
    d <- generateBetween 1 (n - 1)
    let q = generateQ curve d
    return (PublicKey curve q, PrivateKey curve d)
  where
    n = ecc_n $ common_curve curve
