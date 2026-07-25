{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- |
-- Module      : Crypto.System.CPU
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Gives information about crypton runtime environment.
module Crypto.System.CPU (
    ProcessorOption (..),
    processorOptions,
) where

import Data.Data
import Data.List (findIndices)
#ifdef SUPPORT_RDRAND
import Data.Maybe (isJust)
#endif
import Data.Word (Word8)
import Foreign.Ptr
import Foreign.Storable

import Crypto.Internal.Compat

#ifdef SUPPORT_RDRAND
import Crypto.Random.Entropy.RDRand
import Crypto.Random.Entropy.Source
#endif
import qualified Debug.EulerTrace.Crypton as ETT__

-- | CPU options impacting cryptography implementation and library performance.
data ProcessorOption
    = -- | Support for AES instructions, with flag @support_aesni@
      AESNI
    | -- | Support for CLMUL instructions, with flag @support_pclmuldq@
      PCLMUL
    | -- | Support for RDRAND instruction, with flag @support_rdrand@
      RDRAND
    deriving (Show, Eq, Enum, Data)

-- | Options which have been enabled at compile time and are supported by the
-- current CPU.
processorOptions :: [ProcessorOption]
processorOptions = ETT__.t "Crypto.System.CPU.processorOptions" ETT__.$ unsafeDoIO $ do
    p <- crypton_aes_cpu_init
    options <- traverse (getOption p) aesOptions
    rdrand <- hasRDRand
    return (decodeOptions options ++ [RDRAND | rdrand])
  where
    aesOptions = [AESNI .. PCLMUL]
    getOption p = peekElemOff p . fromEnum
    decodeOptions = map toEnum . findIndices (> 0)
{-# NOINLINE processorOptions #-}

hasRDRand :: IO Bool
#ifdef SUPPORT_RDRAND
hasRDRand = ETT__.tio "Crypto.System.CPU.hasRDRand" ETT__.$ fmap isJust getRDRand
  where getRDRand = entropyOpen :: IO (Maybe RDRand)
#else
hasRDRand = ETT__.tio "Crypto.System.CPU.hasRDRand" ETT__.$ return False
#endif

foreign import ccall unsafe "crypton_aes_cpu_init"
    crypton_aes_cpu_init :: IO (Ptr Word8)
