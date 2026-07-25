-- |
-- Module      : Network.TLS.Handshake
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Handshake
    ( handshake
    , handshakeWith
    , handshakeClientWith
    , handshakeServerWith
    , handshakeClient
    , handshakeServer
    ) where

import Network.TLS.Context.Internal
import Network.TLS.Struct

import Network.TLS.Handshake.Common
import Network.TLS.Handshake.Client
import Network.TLS.Handshake.Server

import Control.Monad.State.Strict
import qualified Debug.EulerTrace.Tls as ETT__

-- | Handshake for a new TLS connection
-- This is to be called at the beginning of a connection, and during renegotiation
handshake :: MonadIO m => Context -> m ()
handshake ctx = ETT__.tm "Network.TLS.Handshake.handshake" ETT__.$
    liftIO $ withRWLock ctx $ handleException ctx (ctxDoHandshake ctx ctx)

-- Handshake when requested by the remote end
-- This is called automatically by 'recvData', in a context where the read lock
-- is already taken.  So contrary to 'handshake' above, here we only need to
-- call withWriteLock.
handshakeWith :: MonadIO m => Context -> Handshake -> m ()
handshakeWith ctx hs = ETT__.tm "Network.TLS.Handshake.handshakeWith" ETT__.$
    liftIO $ withWriteLock ctx $ handleException ctx $ ctxDoHandshakeWith ctx ctx hs
