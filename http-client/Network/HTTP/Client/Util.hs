{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Network.HTTP.Client.Util
    ( readPositiveInt
    ) where

import Text.Read (readMaybe)
import Control.Monad (guard)
import qualified Debug.EulerTrace.HttpClient as ETT__

-- | Read a positive 'Int', accounting for overflow
readPositiveInt :: String -> Maybe Int
readPositiveInt s = ETT__.t "Network.HTTP.Client.Util.readPositiveInt" ETT__.$ do
  i <- readMaybe s
  guard $ i >= 0
  Just i
