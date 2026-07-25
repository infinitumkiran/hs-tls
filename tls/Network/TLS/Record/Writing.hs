-- |
-- Module      : Network.TLS.Record.Writing
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- TLS record layer in Tx direction
--
module Network.TLS.Record.Writing
    ( encodeRecord
    , encodeRecord13
    , sendBytes
    ) where

import Network.TLS.Cap
import Network.TLS.Cipher
import Network.TLS.Context.Internal
import Network.TLS.Hooks
import Network.TLS.Imports
import Network.TLS.Packet
import Network.TLS.Parameters
import Network.TLS.Record
import Network.TLS.State
import Network.TLS.Struct

import Control.Concurrent.MVar
import Control.Monad.State.Strict
import qualified Data.ByteString as B
import qualified Debug.EulerTrace.Tls as ETT__

encodeRecord :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
encodeRecord ctx = ETT__.t "Network.TLS.Record.Writing.encodeRecord" ETT__.$ prepareRecord ctx . encodeRecordM

-- before TLS 1.1, the block cipher IV is made of the residual of the previous block,
-- so we use cstIV as is, however in other case we generate an explicit IV
prepareRecord :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord ctx f = ETT__.tio "Network.TLS.Record.Writing.prepareRecord" ETT__.$ do
    ver     <- usingState_ ctx (getVersionWithDefault $ maximum $ supportedVersions $ ctxSupported ctx)
    txState <- readMVar $ ctxTxState ctx
    let sz = case stCipher txState of
                  Nothing     -> 0
                  Just cipher -> if hasRecordIV $ bulkF $ cipherBulk cipher
                                    then bulkIVSize $ cipherBulk cipher
                                    else 0 -- to not generate IV
    if hasExplicitBlockIV ver && sz > 0
        then do newIV <- getStateRNG ctx sz
                runTxState ctx (modify (setRecordIV newIV) >> f)
        else runTxState ctx f

encodeRecordM :: Record Plaintext -> RecordM ByteString
encodeRecordM record = ETT__.tm "Network.TLS.Record.Writing.encodeRecordM" ETT__.$ do
    erecord <- engageRecord record
    let (hdr, content) = recordToRaw erecord
    return $ B.concat [ encodeHeader hdr, content ]

----------------------------------------------------------------

encodeRecord13 :: Context -> Record Plaintext -> IO (Either TLSError ByteString)
encodeRecord13 ctx = ETT__.t "Network.TLS.Record.Writing.encodeRecord13" ETT__.$ prepareRecord13 ctx . encodeRecordM

prepareRecord13 :: Context -> RecordM a -> IO (Either TLSError a)
prepareRecord13 = ETT__.t "Network.TLS.Record.Writing.prepareRecord13" ETT__.$ runTxState

----------------------------------------------------------------

sendBytes :: Context -> ByteString -> IO ()
sendBytes ctx dataToSend = ETT__.tio "Network.TLS.Record.Writing.sendBytes" ETT__.$ do
    withLog ctx $ \logging -> loggingIOSent logging dataToSend
    contextSend ctx dataToSend
