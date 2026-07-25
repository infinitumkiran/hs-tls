{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Network.TLS.RNG
    ( StateRNG(..)
    , Seed
    , seedNew
    , seedToInteger
    , seedFromInteger
    , withTLSRNG
    , newStateRNG
    , MonadRandom
    , getRandomBytes
    ) where

import Crypto.Random.Types
import Crypto.Random
import qualified Debug.EulerTrace.Tls as ETT__

newtype StateRNG = StateRNG ChaChaDRG
    deriving (DRG)

instance Show StateRNG where
    show _ = "rng[..]"

withTLSRNG :: StateRNG
           -> MonadPseudoRandom StateRNG a
           -> (a, StateRNG)
withTLSRNG rng f = ETT__.t "Network.TLS.RNG.withTLSRNG" ETT__.$ withDRG rng f

newStateRNG :: Seed -> StateRNG
newStateRNG seed = ETT__.t "Network.TLS.RNG.newStateRNG" ETT__.$ StateRNG $ drgNewSeed seed
