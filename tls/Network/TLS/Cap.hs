-- |
-- Module      : Network.TLS.Cap
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--

module Network.TLS.Cap
    ( hasHelloExtensions
    , hasExplicitBlockIV
    ) where

import Network.TLS.Types
import qualified Debug.EulerTrace.Tls as ETT__

hasHelloExtensions, hasExplicitBlockIV :: Version -> Bool

hasHelloExtensions ver = ETT__.t "Network.TLS.Cap.hasHelloExtensions" ETT__.$ ver >= SSL3
hasExplicitBlockIV ver = ETT__.t "Network.TLS.Cap.hasExplicitBlockIV" ETT__.$ ver >= TLS11
