{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

-- |
-- Module      : Network.TLS.Packet13
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
module Network.TLS.Packet13
       ( encodeHandshake13
       , getHandshakeType13
       , decodeHandshakeRecord13
       , decodeHandshake13
       , decodeHandshakes13
       ) where

import qualified Data.ByteString as B
import Network.TLS.Struct
import Network.TLS.Struct13
import Network.TLS.Packet
import Network.TLS.Wire
import Network.TLS.Imports
import Data.X509 (CertificateChainRaw(..), encodeCertificateChain, decodeCertificateChain)
import Network.TLS.ErrT
import qualified Debug.EulerTrace.Tls as ETT__

encodeHandshake13 :: Handshake13 -> ByteString
encodeHandshake13 hdsk = ETT__.t "Network.TLS.Packet13.encodeHandshake13" ETT__.$ pkt
  where
    !tp = typeOfHandshake13 hdsk
    !content = encodeHandshake13' hdsk
    !len = B.length content
    !header = encodeHandshakeHeader13 tp len
    !pkt = B.concat [header, content]

-- TLS 1.3 does not use "select (extensions_present)".
putExtensions :: [ExtensionRaw] -> Put
putExtensions es = ETT__.t "Network.TLS.Packet13.putExtensions" ETT__.$ putOpaque16 (runPut $ mapM_ putExtension es)

encodeHandshake13' :: Handshake13 -> ByteString
encodeHandshake13' (ClientHello13 version random session cipherIDs exts) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ do
    putBinaryVersion version
    putClientRandom32 random
    putSession session
    putWords16 cipherIDs
    putWords8 [0]
    putExtensions exts
encodeHandshake13' (ServerHello13 random session cipherId exts) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ do
    putBinaryVersion TLS12
    putServerRandom32 random
    putSession session
    putWord16 cipherId
    putWord8 0 -- compressionID nullCompression
    putExtensions exts
encodeHandshake13' (EncryptedExtensions13 exts) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ putExtensions exts
encodeHandshake13' (CertRequest13 reqctx exts) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ do
    putOpaque8 reqctx
    putExtensions exts
encodeHandshake13' (Certificate13 reqctx cc ess) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ do
    putOpaque8 reqctx
    putOpaque24 (runPut $ mapM_ putCert $ zip certs ess)
  where
    CertificateChainRaw certs = encodeCertificateChain cc
    putCert (certRaw,exts) = do
        putOpaque24 certRaw
        putExtensions exts
encodeHandshake13' (CertVerify13 hs signature) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ do
    putSignatureHashAlgorithm hs
    putOpaque16 signature
encodeHandshake13' (Finished13 dat) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ putBytes dat
encodeHandshake13' (NewSessionTicket13 life ageadd nonce label exts) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ do
    putWord32 life
    putWord32 ageadd
    putOpaque8 nonce
    putOpaque16 label
    putExtensions exts
encodeHandshake13' EndOfEarlyData13 = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ ""
encodeHandshake13' (KeyUpdate13 UpdateNotRequested) = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ putWord8 0
encodeHandshake13' (KeyUpdate13 UpdateRequested)    = ETT__.t "Network.TLS.Packet13.encodeHandshake13'" ETT__.$ runPut $ putWord8 1

encodeHandshakeHeader13 :: HandshakeType13 -> Int -> ByteString
encodeHandshakeHeader13 ty len = ETT__.t "Network.TLS.Packet13.encodeHandshakeHeader13" ETT__.$ runPut $ do
    putWord8 (valOfType ty)
    putWord24 len

decodeHandshakes13 :: MonadError TLSError m => ByteString -> m [Handshake13]
decodeHandshakes13 bs = ETT__.t "Network.TLS.Packet13.decodeHandshakes13" ETT__.$ case decodeHandshakeRecord13 bs of
  GotError err                -> throwError err
  GotPartial _cont            -> error "decodeHandshakes13"
  GotSuccess (ty,content)     -> case decodeHandshake13 ty content of
    Left  e -> throwError e
    Right h -> return [h]
  GotSuccessRemaining (ty,content) left -> case decodeHandshake13 ty content of
    Left  e -> throwError e
    Right h -> (h:) <$> decodeHandshakes13 left

{- decode and encode HANDSHAKE -}
getHandshakeType13 :: Get HandshakeType13
getHandshakeType13 = ETT__.tm "Network.TLS.Packet13.getHandshakeType13" ETT__.$ do
    ty <- getWord8
    case valToType ty of
        Nothing -> fail ("invalid handshake type: " ++ show ty)
        Just t  -> return t

decodeHandshakeRecord13 :: ByteString -> GetResult (HandshakeType13, ByteString)
decodeHandshakeRecord13 = ETT__.t "Network.TLS.Packet13.decodeHandshakeRecord13" ETT__.$ runGet "handshake-record" $ do
    ty      <- getHandshakeType13
    content <- getOpaque24
    return (ty, content)

decodeHandshake13 :: HandshakeType13 -> ByteString -> Either TLSError Handshake13
decodeHandshake13 ty = ETT__.t "Network.TLS.Packet13.decodeHandshake13" ETT__.$ runGetErr ("handshake[" ++ show ty ++ "]") $ case ty of
    HandshakeType_ClientHello13         -> decodeClientHello13
    HandshakeType_ServerHello13         -> decodeServerHello13
    HandshakeType_Finished13            -> decodeFinished13
    HandshakeType_EncryptedExtensions13 -> decodeEncryptedExtensions13
    HandshakeType_CertRequest13         -> decodeCertRequest13
    HandshakeType_Certificate13         -> decodeCertificate13
    HandshakeType_CertVerify13          -> decodeCertVerify13
    HandshakeType_NewSessionTicket13    -> decodeNewSessionTicket13
    HandshakeType_EndOfEarlyData13      -> return EndOfEarlyData13
    HandshakeType_KeyUpdate13           -> decodeKeyUpdate13

decodeClientHello13 :: Get Handshake13
decodeClientHello13 = ETT__.tm "Network.TLS.Packet13.decodeClientHello13" ETT__.$ do
    Just ver <- getBinaryVersion
    random   <- getClientRandom32
    session  <- getSession
    ciphers  <- getWords16
    _comp    <- getWords8
    exts     <- fromIntegral <$> getWord16 >>= getExtensions
    return $ ClientHello13 ver random session ciphers exts

decodeServerHello13 :: Get Handshake13
decodeServerHello13 = ETT__.tm "Network.TLS.Packet13.decodeServerHello13" ETT__.$ do
    Just _ver <- getBinaryVersion
    random    <- getServerRandom32
    session   <- getSession
    cipherid  <- getWord16
    _comp     <- getWord8
    exts      <- fromIntegral <$> getWord16 >>= getExtensions
    return $ ServerHello13 random session cipherid exts

decodeFinished13 :: Get Handshake13
decodeFinished13 = ETT__.tm "Network.TLS.Packet13.decodeFinished13" ETT__.$ Finished13 <$> (remaining >>= getBytes)

decodeEncryptedExtensions13 :: Get Handshake13
decodeEncryptedExtensions13 = ETT__.tm "Network.TLS.Packet13.decodeEncryptedExtensions13" ETT__.$ EncryptedExtensions13 <$> do
    len <- fromIntegral <$> getWord16
    getExtensions len

decodeCertRequest13 :: Get Handshake13
decodeCertRequest13 = ETT__.tm "Network.TLS.Packet13.decodeCertRequest13" ETT__.$ do
    reqctx <- getOpaque8
    len <- fromIntegral <$> getWord16
    exts <- getExtensions len
    return $ CertRequest13 reqctx exts

decodeCertificate13 :: Get Handshake13
decodeCertificate13 = ETT__.tm "Network.TLS.Packet13.decodeCertificate13" ETT__.$ do
    reqctx <- getOpaque8
    len <- fromIntegral <$> getWord24
    (certRaws, ess) <- unzip <$> getList len getCert
    case decodeCertificateChain $ CertificateChainRaw certRaws of
        Left (i, s) -> fail ("error certificate parsing " ++ show i ++ ":" ++ s)
        Right cc    -> return $ Certificate13 reqctx cc ess
  where
    getCert = do
        l <- fromIntegral <$> getWord24
        cert <- getBytes l
        len <- fromIntegral <$> getWord16
        exts <- getExtensions len
        return (3 + l + 2 + len, (cert, exts))

decodeCertVerify13 :: Get Handshake13
decodeCertVerify13 = ETT__.tm "Network.TLS.Packet13.decodeCertVerify13" ETT__.$ CertVerify13 <$> getSignatureHashAlgorithm <*> getOpaque16

decodeNewSessionTicket13 :: Get Handshake13
decodeNewSessionTicket13 = ETT__.tm "Network.TLS.Packet13.decodeNewSessionTicket13" ETT__.$ do
    life   <- getWord32
    ageadd <- getWord32
    nonce  <- getOpaque8
    label  <- getOpaque16
    len    <- fromIntegral <$> getWord16
    exts   <- getExtensions len
    return $ NewSessionTicket13 life ageadd nonce label exts

decodeKeyUpdate13 :: Get Handshake13
decodeKeyUpdate13 = ETT__.tm "Network.TLS.Packet13.decodeKeyUpdate13" ETT__.$ do
    ru <- getWord8
    case ru of
        0 -> return $ KeyUpdate13 UpdateNotRequested
        1 -> return $ KeyUpdate13 UpdateRequested
        x -> fail $ "Unknown request_update: " ++ show x
