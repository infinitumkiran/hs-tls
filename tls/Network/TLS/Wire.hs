-- |
-- Module      : Network.TLS.Wire
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Wire module is a specialized marshalling/unmarshalling package related to the TLS protocol.
-- all multibytes values are written as big endian.
--
module Network.TLS.Wire
    ( Get
    , GetResult(..)
    , GetContinuation
    , runGet
    , runGetErr
    , runGetMaybe
    , tryGet
    , remaining
    , getWord8
    , getWords8
    , getWord16
    , getWords16
    , getWord24
    , getWord32
    , getWord64
    , getBytes
    , getOpaque8
    , getOpaque16
    , getOpaque24
    , getInteger16
    , getBigNum16
    , getList
    , processBytes
    , isEmpty
    , Put
    , runPut
    , putWord8
    , putWords8
    , putWord16
    , putWords16
    , putWord24
    , putWord32
    , putWord64
    , putBytes
    , putOpaque8
    , putOpaque16
    , putOpaque24
    , putInteger16
    , putBigNum16
    , encodeWord16
    , encodeWord32
    , encodeWord64
    ) where

import Data.Serialize.Get hiding (runGet)
import qualified Data.Serialize.Get as G
import Data.Serialize.Put
import qualified Data.ByteString as B
import Network.TLS.Struct
import Network.TLS.Imports
import Network.TLS.Util.Serialization
import qualified Debug.EulerTrace.Tls as ETT__

type GetContinuation a = ByteString -> GetResult a
data GetResult a =
      GotError TLSError
    | GotPartial (GetContinuation a)
    | GotSuccess a
    | GotSuccessRemaining a ByteString

runGet :: String -> Get a -> ByteString -> GetResult a
runGet lbl f = ETT__.t "Network.TLS.Wire.runGet" ETT__.$ toGetResult <$> G.runGetPartial (label lbl f)
  where toGetResult (G.Fail err _)    = GotError (Error_Packet_Parsing err)
        toGetResult (G.Partial cont)  = GotPartial (toGetResult <$> cont)
        toGetResult (G.Done r bsLeft)
            | B.null bsLeft = GotSuccess r
            | otherwise     = GotSuccessRemaining r bsLeft

runGetErr :: String -> Get a -> ByteString -> Either TLSError a
runGetErr lbl getter b = ETT__.t "Network.TLS.Wire.runGetErr" ETT__.$ toSimple $ runGet lbl getter b
  where toSimple (GotError err) = Left err
        toSimple (GotPartial _) = Left (Error_Packet_Parsing (lbl ++ ": parsing error: partial packet"))
        toSimple (GotSuccessRemaining _ _) = Left (Error_Packet_Parsing (lbl ++ ": parsing error: remaining bytes"))
        toSimple (GotSuccess r) = Right r

runGetMaybe :: Get a -> ByteString -> Maybe a
runGetMaybe f = ETT__.t "Network.TLS.Wire.runGetMaybe" ETT__.$ either (const Nothing) Just . G.runGet f

tryGet :: Get a -> ByteString -> Maybe a
tryGet f = ETT__.t "Network.TLS.Wire.tryGet" ETT__.$ either (const Nothing) Just . G.runGet f

getWords8 :: Get [Word8]
getWords8 = ETT__.tm "Network.TLS.Wire.getWords8" ETT__.$ getWord8 >>= \lenb -> replicateM (fromIntegral lenb) getWord8

getWord16 :: Get Word16
getWord16 = ETT__.tm "Network.TLS.Wire.getWord16" ETT__.$ getWord16be

getWords16 :: Get [Word16]
getWords16 = ETT__.tm "Network.TLS.Wire.getWords16" ETT__.$ getWord16 >>= \lenb -> replicateM (fromIntegral lenb `div` 2) getWord16

getWord24 :: Get Int
getWord24 = ETT__.tm "Network.TLS.Wire.getWord24" ETT__.$ do
    a <- fromIntegral <$> getWord8
    b <- fromIntegral <$> getWord8
    c <- fromIntegral <$> getWord8
    return $ (a `shiftL` 16) .|. (b `shiftL` 8) .|. c

getWord32 :: Get Word32
getWord32 = ETT__.tm "Network.TLS.Wire.getWord32" ETT__.$ getWord32be

getWord64 :: Get Word64
getWord64 = ETT__.tm "Network.TLS.Wire.getWord64" ETT__.$ getWord64be

getOpaque8 :: Get ByteString
getOpaque8 = ETT__.tm "Network.TLS.Wire.getOpaque8" ETT__.$ getWord8 >>= getBytes . fromIntegral

getOpaque16 :: Get ByteString
getOpaque16 = ETT__.tm "Network.TLS.Wire.getOpaque16" ETT__.$ getWord16 >>= getBytes . fromIntegral

getOpaque24 :: Get ByteString
getOpaque24 = ETT__.tm "Network.TLS.Wire.getOpaque24" ETT__.$ getWord24 >>= getBytes

getInteger16 :: Get Integer
getInteger16 = ETT__.tm "Network.TLS.Wire.getInteger16" ETT__.$ os2ip <$> getOpaque16

getBigNum16 :: Get BigNum
getBigNum16 = ETT__.tm "Network.TLS.Wire.getBigNum16" ETT__.$ BigNum <$> getOpaque16

getList :: Int -> Get (Int, a) -> Get [a]
getList totalLen getElement = ETT__.tm "Network.TLS.Wire.getList" ETT__.$ isolate totalLen (getElements totalLen)
  where getElements len
            | len < 0     = error "list consumed too much data. should never happen with isolate."
            | len == 0    = return []
            | otherwise   = getElement >>= \(elementLen, a) -> (:) a <$> getElements (len - elementLen)

processBytes :: Int -> Get a -> Get a
processBytes i f = ETT__.tm "Network.TLS.Wire.processBytes" ETT__.$ isolate i f

putWords8 :: [Word8] -> Put
putWords8 l = ETT__.t "Network.TLS.Wire.putWords8" ETT__.$ do
    putWord8 $ fromIntegral (length l)
    mapM_ putWord8 l

putWord16 :: Word16 -> Put
putWord16 = ETT__.t "Network.TLS.Wire.putWord16" ETT__.$ putWord16be

putWord32 :: Word32 -> Put
putWord32 = ETT__.t "Network.TLS.Wire.putWord32" ETT__.$ putWord32be

putWord64 :: Word64 -> Put
putWord64 = ETT__.t "Network.TLS.Wire.putWord64" ETT__.$ putWord64be

putWords16 :: [Word16] -> Put
putWords16 l = ETT__.t "Network.TLS.Wire.putWords16" ETT__.$ do
    putWord16 $ 2 * fromIntegral (length l)
    mapM_ putWord16 l

putWord24 :: Int -> Put
putWord24 i = ETT__.t "Network.TLS.Wire.putWord24" ETT__.$ do
    let a = fromIntegral ((i `shiftR` 16) .&. 0xff)
    let b = fromIntegral ((i `shiftR` 8) .&. 0xff)
    let c = fromIntegral (i .&. 0xff)
    mapM_ putWord8 [a,b,c]

putBytes :: ByteString -> Put
putBytes = ETT__.t "Network.TLS.Wire.putBytes" ETT__.$ putByteString

putOpaque8 :: ByteString -> Put
putOpaque8 b = ETT__.t "Network.TLS.Wire.putOpaque8" ETT__.$ putWord8 (fromIntegral $ B.length b) >> putBytes b

putOpaque16 :: ByteString -> Put
putOpaque16 b = ETT__.t "Network.TLS.Wire.putOpaque16" ETT__.$ putWord16 (fromIntegral $ B.length b) >> putBytes b

putOpaque24 :: ByteString -> Put
putOpaque24 b = ETT__.t "Network.TLS.Wire.putOpaque24" ETT__.$ putWord24 (B.length b) >> putBytes b

putInteger16 :: Integer -> Put
putInteger16 = ETT__.t "Network.TLS.Wire.putInteger16" ETT__.$ putOpaque16 . i2osp

putBigNum16 :: BigNum -> Put
putBigNum16 (BigNum b) = ETT__.t "Network.TLS.Wire.putBigNum16" ETT__.$ putOpaque16 b

encodeWord16 :: Word16 -> ByteString
encodeWord16 = ETT__.t "Network.TLS.Wire.encodeWord16" ETT__.$ runPut . putWord16

encodeWord32 :: Word32 -> ByteString
encodeWord32 = ETT__.t "Network.TLS.Wire.encodeWord32" ETT__.$ runPut . putWord32

encodeWord64 :: Word64 -> ByteString
encodeWord64 = ETT__.t "Network.TLS.Wire.encodeWord64" ETT__.$ runPut . putWord64be
