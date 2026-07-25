-- | Elliptic Curve Arithmetic.
--
-- /WARNING:/ These functions are vulnerable to timing attacks.
module Crypto.PubKey.ECC.Prim (
    scalarGenerate,
    pointAdd,
    pointNegate,
    pointDouble,
    pointBaseMul,
    pointMul,
    pointAddTwoMuls,
    pointDecompose,
    pointCompose,
    isPointAtInfinity,
    isPointValid,
) where

import Crypto.Number.F2m
import Crypto.Number.Generate (generateBetween)
import Crypto.Number.ModArithmetic
import Crypto.PubKey.ECC.Types
import Crypto.Random
import Data.Maybe
import qualified Debug.EulerTrace.Crypton as ETT__

-- | Generate a valid scalar for a specific Curve
scalarGenerate :: MonadRandom randomly => Curve -> randomly PrivateNumber
scalarGenerate curve = ETT__.tm "Crypto.PubKey.ECC.Prim.scalarGenerate" ETT__.$ generateBetween 1 (n - 1)
  where
    n = ecc_n $ common_curve curve

-- TODO: Extract helper function for `fromMaybe PointO...`

-- | Elliptic Curve point negation:
-- @pointNegate c p@ returns point @q@ such that @pointAdd c p q == PointO@.
pointNegate :: Curve -> Point -> Point
pointNegate _ PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointNegate" ETT__.$ PointO
pointNegate (CurveFP c) (Point x y) = ETT__.t "Crypto.PubKey.ECC.Prim.pointNegate" ETT__.$ Point x (ecc_p c - y)
pointNegate CurveF2m{} (Point x y) = ETT__.t "Crypto.PubKey.ECC.Prim.pointNegate" ETT__.$ Point x (x `addF2m` y)

-- | Elliptic Curve point addition.
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAdd :: Curve -> Point -> Point -> Point
pointAdd _ PointO PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointAdd" ETT__.$ PointO
pointAdd _ PointO q = ETT__.t "Crypto.PubKey.ECC.Prim.pointAdd" ETT__.$ q
pointAdd _ p PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointAdd" ETT__.$ p
pointAdd c p q
    | p == q = ETT__.t "Crypto.PubKey.ECC.Prim.pointAdd" ETT__.$ pointDouble c p
    | p == pointNegate c q = ETT__.t "Crypto.PubKey.ECC.Prim.pointAdd" ETT__.$ PointO
pointAdd (CurveFP (CurvePrime pr _)) (Point xp yp) (Point xq yq) = ETT__.t "Crypto.PubKey.ECC.Prim.pointAdd" ETT__.$
    fromMaybe PointO $ do
        s <- divmod (yp - yq) (xp - xq) pr
        let xr = (s ^ (2 :: Int) - xp - xq) `mod` pr
            yr = (s * (xp - xr) - yp) `mod` pr
        return $ Point xr yr
pointAdd (CurveF2m (CurveBinary fx cc)) (Point xp yp) (Point xq yq) = ETT__.t "Crypto.PubKey.ECC.Prim.pointAdd" ETT__.$
    fromMaybe PointO $ do
        s <- divF2m fx (yp `addF2m` yq) (xp `addF2m` xq)
        let xr = mulF2m fx s s `addF2m` s `addF2m` xp `addF2m` xq `addF2m` a
            yr = mulF2m fx s (xp `addF2m` xr) `addF2m` xr `addF2m` yp
        return $ Point xr yr
  where
    a = ecc_a cc

-- | Elliptic Curve point doubling.
--
-- /WARNING:/ Vulnerable to timing attacks.
--
-- This perform the following calculation:
-- > lambda = (3 * xp ^ 2 + a) / 2 yp
-- > xr = lambda ^ 2 - 2 xp
-- > yr = lambda (xp - xr) - yp
--
-- With binary curve:
-- > xp == 0   => P = O
-- > otherwise =>
-- >    s = xp + (yp / xp)
-- >    xr = s ^ 2 + s + a
-- >    yr = xp ^ 2 + (s+1) * xr
pointDouble :: Curve -> Point -> Point
pointDouble _ PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointDouble" ETT__.$ PointO
pointDouble (CurveFP (CurvePrime pr cc)) (Point xp yp) = ETT__.t "Crypto.PubKey.ECC.Prim.pointDouble" ETT__.$ fromMaybe PointO $ do
    lambda <- divmod (3 * xp ^ (2 :: Int) + a) (2 * yp) pr
    let xr = (lambda ^ (2 :: Int) - 2 * xp) `mod` pr
        yr = (lambda * (xp - xr) - yp) `mod` pr
    return $ Point xr yr
  where
    a = ecc_a cc
pointDouble (CurveF2m (CurveBinary fx cc)) (Point xp yp)
    | xp == 0 = ETT__.t "Crypto.PubKey.ECC.Prim.pointDouble" ETT__.$ PointO
    | otherwise = ETT__.t "Crypto.PubKey.ECC.Prim.pointDouble" ETT__.$ fromMaybe PointO $ do
        s <- return . addF2m xp =<< divF2m fx yp xp
        let xr = mulF2m fx s s `addF2m` s `addF2m` a
            yr = mulF2m fx xp xp `addF2m` mulF2m fx xr (s `addF2m` 1)
        return $ Point xr yr
  where
    a = ecc_a cc

-- | Elliptic curve point multiplication using the base
--
-- /WARNING:/ Vulnerable to timing attacks.
pointBaseMul :: Curve -> Integer -> Point
pointBaseMul c n = ETT__.t "Crypto.PubKey.ECC.Prim.pointBaseMul" ETT__.$ pointMul c n (ecc_g $ common_curve c)

-- | Elliptic curve point multiplication (double and add algorithm).
--
-- /WARNING:/ Vulnerable to timing attacks.
pointMul :: Curve -> Integer -> Point -> Point
pointMul _ _ PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointMul" ETT__.$ PointO
pointMul c n p
    | n < 0 = ETT__.t "Crypto.PubKey.ECC.Prim.pointMul" ETT__.$ pointMul c (-n) (pointNegate c p)
    | n == 0 = ETT__.t "Crypto.PubKey.ECC.Prim.pointMul" ETT__.$ PointO
    | n == 1 = ETT__.t "Crypto.PubKey.ECC.Prim.pointMul" ETT__.$ p
    | odd n = ETT__.t "Crypto.PubKey.ECC.Prim.pointMul" ETT__.$ pointAdd c p (pointMul c (n - 1) p)
    | otherwise = ETT__.t "Crypto.PubKey.ECC.Prim.pointMul" ETT__.$ pointMul c (n `div` 2) (pointDouble c p)

-- | Elliptic curve double-scalar multiplication (uses Shamir's trick).
--
-- > pointAddTwoMuls c n1 p1 n2 p2 == pointAdd c (pointMul c n1 p1)
-- >                                             (pointMul c n2 p2)
--
-- /WARNING:/ Vulnerable to timing attacks.
pointAddTwoMuls :: Curve -> Integer -> Point -> Integer -> Point -> Point
pointAddTwoMuls _ _ PointO _ PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointAddTwoMuls" ETT__.$ PointO
pointAddTwoMuls c _ PointO n2 p2 = ETT__.t "Crypto.PubKey.ECC.Prim.pointAddTwoMuls" ETT__.$ pointMul c n2 p2
pointAddTwoMuls c n1 p1 _ PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointAddTwoMuls" ETT__.$ pointMul c n1 p1
pointAddTwoMuls c n1 p1 n2 p2
    | n1 < 0 = ETT__.t "Crypto.PubKey.ECC.Prim.pointAddTwoMuls" ETT__.$ pointAddTwoMuls c (-n1) (pointNegate c p1) n2 p2
    | n2 < 0 = ETT__.t "Crypto.PubKey.ECC.Prim.pointAddTwoMuls" ETT__.$ pointAddTwoMuls c n1 p1 (-n2) (pointNegate c p2)
    | otherwise = ETT__.t "Crypto.PubKey.ECC.Prim.pointAddTwoMuls" ETT__.$ go (n1, n2)
  where
    p0 = pointAdd c p1 p2

    go (0, 0) = PointO
    go (k1, k2) =
        let q = pointDouble c $ go (k1 `div` 2, k2 `div` 2)
         in case (odd k1, odd k2) of
                (True, True) -> pointAdd c p0 q
                (True, False) -> pointAdd c p1 q
                (False, True) -> pointAdd c p2 q
                (False, False) -> q

-- | Decompose a point into index, residue, and parity.
--
-- Adapted from SEC 1: Elliptic Curve Cryptography, Version 2.0, section 2.3.3.
pointDecompose :: Curve -> Point -> Maybe (Integer, Integer, Bool)
pointDecompose _ PointO = ETT__.t "Crypto.PubKey.ECC.Prim.pointDecompose" ETT__.$ Nothing
pointDecompose curve (Point x y) = ETT__.t "Crypto.PubKey.ECC.Prim.pointDecompose" ETT__.$ do
    let CurveCommon _ _ _ n _ = common_curve curve
    let (index, residue) = x `divMod` n
    parity <- case curve of
        CurveFP _ -> pure $ odd y
        CurveF2m _ | x == 0 -> pure False
        CurveF2m (CurveBinary fx _) -> odd <$> divF2m fx y x
    pure (index, residue, parity)

-- | Compose a point from index, residue, and parity.
--
-- Adapted from SEC 1: Elliptic Curve Cryptography, Version 2.0, section 2.3.4.
pointCompose :: Curve -> Integer -> Integer -> Bool -> Maybe Point
pointCompose curve index residue parity = ETT__.t "Crypto.PubKey.ECC.Prim.pointCompose" ETT__.$ do
    let CurveCommon a b _ n _ = common_curve curve
    let x = residue + index * n
    y <- case curve of
        CurveFP (CurvePrime p _) -> do
            z <- squareRoot p $ x ^ (3 :: Int) + a * x + b
            pure $ if odd z == parity then z else p - z
        CurveF2m (CurveBinary fx _) | x == 0 -> pure $ sqrtF2m fx b
        CurveF2m (CurveBinary fx _) -> do
            c <- divF2m fx b $ squareF2m fx x
            z <- quadraticF2m fx $ addF2m x $ addF2m a c
            pure $ mulF2m fx x $ if odd z == parity then z else addF2m 1 z
    pure $ Point x y

-- | Check if a point is the point at infinity.
isPointAtInfinity :: Point -> Bool
isPointAtInfinity PointO = ETT__.t "Crypto.PubKey.ECC.Prim.isPointAtInfinity" ETT__.$ True
isPointAtInfinity _ = ETT__.t "Crypto.PubKey.ECC.Prim.isPointAtInfinity" ETT__.$ False

-- | check if a point is on specific curve
--
-- This perform three checks:
--
-- * x is not out of range
-- * y is not out of range
-- * the equation @y^2 = x^3 + a*x + b (mod p)@ holds
isPointValid :: Curve -> Point -> Bool
isPointValid _ PointO = ETT__.t "Crypto.PubKey.ECC.Prim.isPointValid" ETT__.$ True
isPointValid (CurveFP (CurvePrime p cc)) (Point x y) = ETT__.t "Crypto.PubKey.ECC.Prim.isPointValid" ETT__.$
    isValid x && isValid y && (y ^ (2 :: Int)) `eqModP` (x ^ (3 :: Int) + a * x + b)
  where
    a = ecc_a cc
    b = ecc_b cc
    eqModP z1 z2 = (z1 `mod` p) == (z2 `mod` p)
    isValid e = e >= 0 && e < p
isPointValid (CurveF2m (CurveBinary fx cc)) (Point x y) = ETT__.t "Crypto.PubKey.ECC.Prim.isPointValid" ETT__.$
    and
        [ isValid x
        , isValid y
        , ((((x `add` a) `mul` x `add` y) `mul` x) `add` b `add` (squareF2m fx y)) == 0
        ]
  where
    a = ecc_a cc
    b = ecc_b cc
    add = addF2m
    mul = mulF2m fx
    isValid e = modF2m fx e == e

-- | div and mod
divmod :: Integer -> Integer -> Integer -> Maybe Integer
divmod y x m = ETT__.t "Crypto.PubKey.ECC.Prim.divmod" ETT__.$ do
    i <- inverse (x `mod` m) m
    return $ y * i `mod` m
