{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module      : Network.TLS.Packet
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : unknown
--
-- the Packet module contains everything necessary to serialize and deserialize things
-- with only explicit parameters, no TLS state is involved here.
--
module Network.TLS.Packet
    (
    -- * params for encoding and decoding
      CurrentParams(..)
    -- * marshall functions for header messages
    , decodeHeader
    , decodeDeprecatedHeaderLength
    , decodeDeprecatedHeader
    , encodeHeader
    , encodeHeaderNoVer -- use for SSL3

    -- * marshall functions for alert messages
    , decodeAlert
    , decodeAlerts
    , encodeAlerts

    -- * marshall functions for handshake messages
    , decodeHandshakeRecord
    , decodeHandshake
    , decodeDeprecatedHandshake
    , encodeHandshake
    , encodeHandshakeHeader
    , encodeHandshakeContent

    -- * marshall functions for change cipher spec message
    , decodeChangeCipherSpec
    , encodeChangeCipherSpec

    , decodePreMasterSecret
    , encodePreMasterSecret
    , encodeSignedDHParams
    , encodeSignedECDHParams

    , decodeReallyServerKeyXchgAlgorithmData

    -- * generate things for packet content
    , generateMasterSecret
    , generateExtendedMasterSec
    , generateKeyBlock
    , generateClientFinished
    , generateServerFinished

    , generateCertificateVerify_SSL
    , generateCertificateVerify_SSL_DSS

    -- * for extensions parsing
    , getSignatureHashAlgorithm
    , putSignatureHashAlgorithm
    , getBinaryVersion
    , putBinaryVersion
    , getClientRandom32
    , putClientRandom32
    , getServerRandom32
    , putServerRandom32
    , getExtensions
    , putExtension
    , getSession
    , putSession
    , putDNames
    , getDNames
    ) where

import Network.TLS.Imports
import Network.TLS.Struct
import Network.TLS.Wire
import Network.TLS.Cap
import Data.X509 (CertificateChainRaw(..), encodeCertificateChain, decodeCertificateChain)
import Network.TLS.Crypto
import Network.TLS.MAC
import Network.TLS.Cipher (CipherKeyExchangeType(..), Cipher(..))
import Network.TLS.Util.ASN1
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import           Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as B (convert)
import qualified Debug.EulerTrace.Tls as ETT__

data CurrentParams = CurrentParams
    { cParamsVersion     :: Version                     -- ^ current protocol version
    , cParamsKeyXchgType :: Maybe CipherKeyExchangeType -- ^ current key exchange type
    } deriving (Show,Eq)

{- marshall helpers -}
getVersion :: Get Version
getVersion = ETT__.tm "Network.TLS.Packet.getVersion" ETT__.$ do
    major <- getWord8
    minor <- getWord8
    case verOfNum (major, minor) of
        Nothing -> fail ("invalid version : " ++ show major ++ "," ++ show minor)
        Just v  -> return v

getBinaryVersion :: Get (Maybe Version)
getBinaryVersion = ETT__.tm "Network.TLS.Packet.getBinaryVersion" ETT__.$ do
    major <- getWord8
    minor <- getWord8
    return $ verOfNum (major, minor)

putBinaryVersion :: Version -> Put
putBinaryVersion ver = ETT__.t "Network.TLS.Packet.putBinaryVersion" ETT__.$ putWord8 major >> putWord8 minor
  where (major, minor) = numericalVer ver

getHeaderType :: Get ProtocolType
getHeaderType = ETT__.tm "Network.TLS.Packet.getHeaderType" ETT__.$ do
    ty <- getWord8
    case valToType ty of
        Nothing -> fail ("invalid header type: " ++ show ty)
        Just t  -> return t

putHeaderType :: ProtocolType -> Put
putHeaderType = ETT__.t "Network.TLS.Packet.putHeaderType" ETT__.$ putWord8 . valOfType

getHandshakeType :: Get HandshakeType
getHandshakeType = ETT__.tm "Network.TLS.Packet.getHandshakeType" ETT__.$ do
    ty <- getWord8
    case valToType ty of
        Nothing -> fail ("invalid handshake type: " ++ show ty)
        Just t  -> return t

{-
 - decode and encode headers
 -}
decodeHeader :: ByteString -> Either TLSError Header
decodeHeader = ETT__.t "Network.TLS.Packet.decodeHeader" ETT__.$ runGetErr "header" $ Header <$> getHeaderType <*> getVersion <*> getWord16

decodeDeprecatedHeaderLength :: ByteString -> Either TLSError Word16
decodeDeprecatedHeaderLength = ETT__.t "Network.TLS.Packet.decodeDeprecatedHeaderLength" ETT__.$ runGetErr "deprecatedheaderlength" $ subtract 0x8000 <$> getWord16

decodeDeprecatedHeader :: Word16 -> ByteString -> Either TLSError Header
decodeDeprecatedHeader size = ETT__.t "Network.TLS.Packet.decodeDeprecatedHeader" ETT__.$
    runGetErr "deprecatedheader" $ do
        1 <- getWord8
        version <- getVersion
        return $ Header ProtocolType_DeprecatedHandshake version size

encodeHeader :: Header -> ByteString
encodeHeader (Header pt ver len) = ETT__.t "Network.TLS.Packet.encodeHeader" ETT__.$ runPut (putHeaderType pt >> putBinaryVersion ver >> putWord16 len)
        {- FIXME check len <= 2^14 -}

encodeHeaderNoVer :: Header -> ByteString
encodeHeaderNoVer (Header pt _ len) = ETT__.t "Network.TLS.Packet.encodeHeaderNoVer" ETT__.$ runPut (putHeaderType pt >> putWord16 len)
        {- FIXME check len <= 2^14 -}

{-
 - decode and encode ALERT
 -}
decodeAlert :: Get (AlertLevel, AlertDescription)
decodeAlert = ETT__.tm "Network.TLS.Packet.decodeAlert" ETT__.$ do
    al <- getWord8
    ad <- getWord8
    case (valToType al, valToType ad) of
        (Just a, Just d) -> return (a, d)
        (Nothing, _)     -> fail "cannot decode alert level"
        (_, Nothing)     -> fail "cannot decode alert description"

decodeAlerts :: ByteString -> Either TLSError [(AlertLevel, AlertDescription)]
decodeAlerts = ETT__.t "Network.TLS.Packet.decodeAlerts" ETT__.$ runGetErr "alerts" loop
  where loop = do
            r <- remaining
            if r == 0
                then return []
                else (:) <$> decodeAlert <*> loop

encodeAlerts :: [(AlertLevel, AlertDescription)] -> ByteString
encodeAlerts l = ETT__.t "Network.TLS.Packet.encodeAlerts" ETT__.$ runPut $ mapM_ encodeAlert l
  where encodeAlert (al, ad) = putWord8 (valOfType al) >> putWord8 (valOfType ad)

{- decode and encode HANDSHAKE -}
decodeHandshakeRecord :: ByteString -> GetResult (HandshakeType, ByteString)
decodeHandshakeRecord = ETT__.t "Network.TLS.Packet.decodeHandshakeRecord" ETT__.$ runGet "handshake-record" $ do
    ty      <- getHandshakeType
    content <- getOpaque24
    return (ty, content)

decodeHandshake :: CurrentParams -> HandshakeType -> ByteString -> Either TLSError Handshake
decodeHandshake cp ty = ETT__.t "Network.TLS.Packet.decodeHandshake" ETT__.$ runGetErr ("handshake[" ++ show ty ++ "]") $ case ty of
    HandshakeType_HelloRequest    -> decodeHelloRequest
    HandshakeType_ClientHello     -> decodeClientHello
    HandshakeType_ServerHello     -> decodeServerHello
    HandshakeType_Certificate     -> decodeCertificates
    HandshakeType_ServerKeyXchg   -> decodeServerKeyXchg cp
    HandshakeType_CertRequest     -> decodeCertRequest cp
    HandshakeType_ServerHelloDone -> decodeServerHelloDone
    HandshakeType_CertVerify      -> decodeCertVerify cp
    HandshakeType_ClientKeyXchg   -> decodeClientKeyXchg cp
    HandshakeType_Finished        -> decodeFinished

decodeDeprecatedHandshake :: ByteString -> Either TLSError Handshake
decodeDeprecatedHandshake b = ETT__.t "Network.TLS.Packet.decodeDeprecatedHandshake" ETT__.$ runGetErr "deprecatedhandshake" getDeprecated b
  where getDeprecated = do
            1 <- getWord8
            ver <- getVersion
            cipherSpecLen <- fromEnum <$> getWord16
            sessionIdLen <- fromEnum <$> getWord16
            challengeLen <- fromEnum <$> getWord16
            ciphers <- getCipherSpec cipherSpecLen
            session <- getSessionId sessionIdLen
            random <- getChallenge challengeLen
            let compressions = [0]
            return $ ClientHello ver random session ciphers compressions [] (Just b)
        getCipherSpec len | len < 3 = return []
        getCipherSpec len = do
            [c0,c1,c2] <- map fromEnum <$> replicateM 3 getWord8
            ([ toEnum $ c1 * 0x100 + c2 | c0 == 0 ] ++) <$> getCipherSpec (len - 3)
        getSessionId 0 = return $ Session Nothing
        getSessionId len = Session . Just <$> getBytes len
        getChallenge len | 32 < len = getBytes (len - 32) >> getChallenge 32
        getChallenge len = ClientRandom . B.append (B.replicate (32 - len) 0) <$> getBytes len

decodeHelloRequest :: Get Handshake
decodeHelloRequest = ETT__.tm "Network.TLS.Packet.decodeHelloRequest" ETT__.$ return HelloRequest

decodeClientHello :: Get Handshake
decodeClientHello = ETT__.tm "Network.TLS.Packet.decodeClientHello" ETT__.$ do
    ver          <- getVersion
    random       <- getClientRandom32
    session      <- getSession
    ciphers      <- getWords16
    compressions <- getWords8
    r            <- remaining
    exts <- if hasHelloExtensions ver && r > 0
            then fromIntegral <$> getWord16 >>= getExtensions
            else do
               rest <- remaining
               _ <- getBytes rest
               return []
    return $ ClientHello ver random session ciphers compressions exts Nothing

decodeServerHello :: Get Handshake
decodeServerHello = ETT__.tm "Network.TLS.Packet.decodeServerHello" ETT__.$ do
    ver           <- getVersion
    random        <- getServerRandom32
    session       <- getSession
    cipherid      <- getWord16
    compressionid <- getWord8
    r             <- remaining
    exts <- if hasHelloExtensions ver && r > 0
            then fromIntegral <$> getWord16 >>= getExtensions
            else return []
    return $ ServerHello ver random session cipherid compressionid exts

decodeServerHelloDone :: Get Handshake
decodeServerHelloDone = ETT__.tm "Network.TLS.Packet.decodeServerHelloDone" ETT__.$ return ServerHelloDone

decodeCertificates :: Get Handshake
decodeCertificates = ETT__.tm "Network.TLS.Packet.decodeCertificates" ETT__.$ do
    certsRaw <- CertificateChainRaw <$> (getWord24 >>= \len -> getList (fromIntegral len) getCertRaw)
    case decodeCertificateChain certsRaw of
        Left (i, s) -> fail ("error certificate parsing " ++ show i ++ ":" ++ s)
        Right cc    -> return $ Certificates cc
  where getCertRaw = getOpaque24 >>= \cert -> return (3 + B.length cert, cert)

decodeFinished :: Get Handshake
decodeFinished = ETT__.tm "Network.TLS.Packet.decodeFinished" ETT__.$ Finished <$> (remaining >>= getBytes)

decodeCertRequest :: CurrentParams -> Get Handshake
decodeCertRequest cp = ETT__.tm "Network.TLS.Packet.decodeCertRequest" ETT__.$ do
    mcertTypes <- map (valToType . fromIntegral) <$> getWords8
    certTypes <- mapM (fromJustM "decodeCertRequest") mcertTypes
    sigHashAlgs <- if cParamsVersion cp >= TLS12
                       then Just <$> (getWord16 >>= getSignatureHashAlgorithms)
                       else return Nothing
    CertRequest certTypes sigHashAlgs <$> getDNames
  where getSignatureHashAlgorithms len = getList (fromIntegral len) (getSignatureHashAlgorithm >>= \sh -> return (2, sh))

-- | Decode a list CA distinguished names
getDNames :: Get [DistinguishedName]
getDNames = ETT__.tm "Network.TLS.Packet.getDNames" ETT__.$ do
    dNameLen <- getWord16
    -- FIXME: Decide whether to remove this check completely or to make it an option.
    -- when (cParamsVersion cp < TLS12 && dNameLen < 3) $ fail "certrequest distinguishname not of the correct size"
    getList (fromIntegral dNameLen) getDName
  where
    getDName = do
        dName <- getOpaque16
        when (B.length dName == 0) $ fail "certrequest: invalid DN length"
        dn <- either fail return $ decodeASN1Object "cert request DistinguishedName" dName
        return (2 + B.length dName, dn)

decodeCertVerify :: CurrentParams -> Get Handshake
decodeCertVerify cp = ETT__.tm "Network.TLS.Packet.decodeCertVerify" ETT__.$ CertVerify <$> getDigitallySigned (cParamsVersion cp)

decodeClientKeyXchg :: CurrentParams -> Get Handshake
decodeClientKeyXchg cp = ETT__.tm "Network.TLS.Packet.decodeClientKeyXchg" ETT__.$ -- case  ClientKeyXchg <$> (remaining >>= getBytes)
    case cParamsKeyXchgType cp of
        Nothing  -> error "no client key exchange type"
        Just cke -> ClientKeyXchg <$> parseCKE cke
  where parseCKE CipherKeyExchange_RSA     = CKX_RSA <$> (remaining >>= getBytes)
        parseCKE CipherKeyExchange_DHE_RSA = parseClientDHPublic
        parseCKE CipherKeyExchange_DHE_DSS = parseClientDHPublic
        parseCKE CipherKeyExchange_DH_Anon = parseClientDHPublic
        parseCKE CipherKeyExchange_ECDHE_RSA   = parseClientECDHPublic
        parseCKE CipherKeyExchange_ECDHE_ECDSA = parseClientECDHPublic
        parseCKE _                         = error "unsupported client key exchange type"
        parseClientDHPublic = CKX_DH . dhPublic <$> getInteger16
        parseClientECDHPublic = CKX_ECDH <$> getOpaque8

decodeServerKeyXchg_DH :: Get ServerDHParams
decodeServerKeyXchg_DH = ETT__.tm "Network.TLS.Packet.decodeServerKeyXchg_DH" ETT__.$ getServerDHParams

-- We don't support ECDH_Anon at this moment
-- decodeServerKeyXchg_ECDH :: Get ServerECDHParams

decodeServerKeyXchg_RSA :: Get ServerRSAParams
decodeServerKeyXchg_RSA = ETT__.tm "Network.TLS.Packet.decodeServerKeyXchg_RSA" ETT__.$ ServerRSAParams <$> getInteger16 -- modulus
                                          <*> getInteger16 -- exponent

decodeServerKeyXchgAlgorithmData :: Version
                                 -> CipherKeyExchangeType
                                 -> Get ServerKeyXchgAlgorithmData
decodeServerKeyXchgAlgorithmData ver cke = ETT__.tm "Network.TLS.Packet.decodeServerKeyXchgAlgorithmData" ETT__.$ toCKE
  where toCKE = case cke of
            CipherKeyExchange_RSA     -> SKX_RSA . Just <$> decodeServerKeyXchg_RSA
            CipherKeyExchange_DH_Anon -> SKX_DH_Anon <$> decodeServerKeyXchg_DH
            CipherKeyExchange_DHE_RSA -> do
                dhparams  <- getServerDHParams
                signature <- getDigitallySigned ver
                return $ SKX_DHE_RSA dhparams signature
            CipherKeyExchange_DHE_DSS -> do
                dhparams  <- getServerDHParams
                signature <- getDigitallySigned ver
                return $ SKX_DHE_DSS dhparams signature
            CipherKeyExchange_ECDHE_RSA -> do
                ecdhparams  <- getServerECDHParams
                signature <- getDigitallySigned ver
                return $ SKX_ECDHE_RSA ecdhparams signature
            CipherKeyExchange_ECDHE_ECDSA -> do
                ecdhparams  <- getServerECDHParams
                signature <- getDigitallySigned ver
                return $ SKX_ECDHE_ECDSA ecdhparams signature
            _ -> do
                bs <- remaining >>= getBytes
                return $ SKX_Unknown bs

decodeServerKeyXchg :: CurrentParams -> Get Handshake
decodeServerKeyXchg cp = ETT__.tm "Network.TLS.Packet.decodeServerKeyXchg" ETT__.$
    case cParamsKeyXchgType cp of
        Just cke -> ServerKeyXchg <$> decodeServerKeyXchgAlgorithmData (cParamsVersion cp) cke
        Nothing  -> ServerKeyXchg . SKX_Unparsed <$> (remaining >>= getBytes)

encodeHandshake :: Handshake -> ByteString
encodeHandshake o = ETT__.t "Network.TLS.Packet.encodeHandshake" ETT__.$
    let content = runPut $ encodeHandshakeContent o in
    let len = B.length content in
    let header = case o of
                    ClientHello _ _ _ _ _ _ (Just _) -> "" -- SSLv2 ClientHello message
                    _ -> runPut $ encodeHandshakeHeader (typeOfHandshake o) len in
    B.concat [ header, content ]

encodeHandshakeHeader :: HandshakeType -> Int -> Put
encodeHandshakeHeader ty len = ETT__.t "Network.TLS.Packet.encodeHandshakeHeader" ETT__.$ putWord8 (valOfType ty) >> putWord24 len

encodeHandshakeContent :: Handshake -> Put

encodeHandshakeContent (ClientHello _ _ _ _ _ _ (Just deprecated)) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ do
    putBytes deprecated
encodeHandshakeContent (ClientHello version random session cipherIDs compressionIDs exts Nothing) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ do
    putBinaryVersion version
    putClientRandom32 random
    putSession session
    putWords16 cipherIDs
    putWords8 compressionIDs
    putExtensions exts
    return ()

encodeHandshakeContent (ServerHello version random session cipherid compressionID exts) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ do
    putBinaryVersion version
    putServerRandom32 random
    putSession session
    putWord16 cipherid
    putWord8 compressionID
    putExtensions exts
    return ()

encodeHandshakeContent (Certificates cc) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ putOpaque24 (runPut $ mapM_ putOpaque24 certs)
  where (CertificateChainRaw certs) = encodeCertificateChain cc

encodeHandshakeContent (ClientKeyXchg ckx) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ do
    case ckx of
        CKX_RSA encryptedPreMaster -> putBytes encryptedPreMaster
        CKX_DH clientDHPublic      -> putInteger16 $ dhUnwrapPublic clientDHPublic
        CKX_ECDH bytes             -> putOpaque8 bytes

encodeHandshakeContent (ServerKeyXchg skg) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$
    case skg of
        SKX_RSA _              -> error "encodeHandshakeContent SKX_RSA not implemented"
        SKX_DH_Anon params     -> putServerDHParams params
        SKX_DHE_RSA params sig -> putServerDHParams params >> putDigitallySigned sig
        SKX_DHE_DSS params sig -> putServerDHParams params >> putDigitallySigned sig
        SKX_ECDHE_RSA params sig -> putServerECDHParams params >> putDigitallySigned sig
        SKX_ECDHE_ECDSA params sig -> putServerECDHParams params >> putDigitallySigned sig
        SKX_Unparsed bytes     -> putBytes bytes
        _                      -> error ("encodeHandshakeContent: cannot handle: " ++ show skg)

encodeHandshakeContent HelloRequest    = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ return ()
encodeHandshakeContent ServerHelloDone = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ return ()

encodeHandshakeContent (CertRequest certTypes sigAlgs certAuthorities) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ do
    putWords8 (map valOfType certTypes)
    case sigAlgs of
        Nothing -> return ()
        Just l  -> putWords16 $ map (\(x,y) -> fromIntegral (valOfType x) * 256 + fromIntegral (valOfType y)) l
    putDNames certAuthorities

encodeHandshakeContent (CertVerify digitallySigned) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ putDigitallySigned digitallySigned

encodeHandshakeContent (Finished opaque) = ETT__.t "Network.TLS.Packet.encodeHandshakeContent" ETT__.$ putBytes opaque

------------------------------------------------------------

-- | Encode a list of distinguished names.
putDNames :: [DistinguishedName] -> Put
putDNames dnames = ETT__.t "Network.TLS.Packet.putDNames" ETT__.$ do
    enc <- mapM encodeCA dnames
    let totLength = sum $ map ((+) 2 . B.length) enc
    putWord16 (fromIntegral totLength)
    mapM_ (\ b -> putWord16 (fromIntegral (B.length b)) >> putBytes b) enc
  where
    -- Convert a distinguished name to its DER encoding.
    encodeCA dn = return $ encodeASN1Object dn

{- FIXME make sure it return error if not 32 available -}
getRandom32 :: Get ByteString
getRandom32 = ETT__.tm "Network.TLS.Packet.getRandom32" ETT__.$ getBytes 32

getServerRandom32 :: Get ServerRandom
getServerRandom32 = ETT__.tm "Network.TLS.Packet.getServerRandom32" ETT__.$ ServerRandom <$> getRandom32

getClientRandom32 :: Get ClientRandom
getClientRandom32 = ETT__.tm "Network.TLS.Packet.getClientRandom32" ETT__.$ ClientRandom <$> getRandom32

putRandom32 :: ByteString -> Put
putRandom32 = ETT__.t "Network.TLS.Packet.putRandom32" ETT__.$ putBytes

putClientRandom32 :: ClientRandom -> Put
putClientRandom32 (ClientRandom r) = ETT__.t "Network.TLS.Packet.putClientRandom32" ETT__.$ putRandom32 r

putServerRandom32 :: ServerRandom -> Put
putServerRandom32 (ServerRandom r) = ETT__.t "Network.TLS.Packet.putServerRandom32" ETT__.$ putRandom32 r

getSession :: Get Session
getSession = ETT__.tm "Network.TLS.Packet.getSession" ETT__.$ do
    len8 <- getWord8
    case fromIntegral len8 of
        0   -> return $ Session Nothing
        len -> Session . Just <$> getBytes len

putSession :: Session -> Put
putSession (Session Nothing)  = ETT__.t "Network.TLS.Packet.putSession" ETT__.$ putWord8 0
putSession (Session (Just s)) = ETT__.t "Network.TLS.Packet.putSession" ETT__.$ putOpaque8 s

getExtensions :: Int -> Get [ExtensionRaw]
getExtensions 0   = ETT__.t "Network.TLS.Packet.getExtensions" ETT__.$ return []
getExtensions len = ETT__.tm "Network.TLS.Packet.getExtensions" ETT__.$ do
    extty <- getWord16
    extdatalen <- getWord16
    extdata <- getBytes $ fromIntegral extdatalen
    extxs <- getExtensions (len - fromIntegral extdatalen - 4)
    return $ ExtensionRaw extty extdata : extxs

putExtension :: ExtensionRaw -> Put
putExtension (ExtensionRaw ty l) = ETT__.t "Network.TLS.Packet.putExtension" ETT__.$ putWord16 ty >> putOpaque16 l

putExtensions :: [ExtensionRaw] -> Put
putExtensions [] = ETT__.t "Network.TLS.Packet.putExtensions" ETT__.$ return ()
putExtensions es = ETT__.t "Network.TLS.Packet.putExtensions" ETT__.$ putOpaque16 (runPut $ mapM_ putExtension es)

getSignatureHashAlgorithm :: Get HashAndSignatureAlgorithm
getSignatureHashAlgorithm = ETT__.tm "Network.TLS.Packet.getSignatureHashAlgorithm" ETT__.$ do
    h <- (valToType <$> getWord8) >>= fromJustM "getSignatureHashAlgorithm"
    s <- (valToType <$> getWord8) >>= fromJustM "getSignatureHashAlgorithm"
    return (h,s)

putSignatureHashAlgorithm :: HashAndSignatureAlgorithm -> Put
putSignatureHashAlgorithm (h,s) = ETT__.t "Network.TLS.Packet.putSignatureHashAlgorithm" ETT__.$
    putWord8 (valOfType h) >> putWord8 (valOfType s)

getServerDHParams :: Get ServerDHParams
getServerDHParams = ETT__.tm "Network.TLS.Packet.getServerDHParams" ETT__.$ ServerDHParams <$> getBigNum16 <*> getBigNum16 <*> getBigNum16

putServerDHParams :: ServerDHParams -> Put
putServerDHParams (ServerDHParams p g y) = ETT__.t "Network.TLS.Packet.putServerDHParams" ETT__.$ mapM_ putBigNum16 [p,g,y]

-- RFC 4492 Section 5.4 Server Key Exchange
getServerECDHParams :: Get ServerECDHParams
getServerECDHParams = ETT__.tm "Network.TLS.Packet.getServerECDHParams" ETT__.$ do
    curveType <- getWord8
    case curveType of
        3 -> do               -- ECParameters ECCurveType: curve name type
            mgrp <- toEnumSafe16 <$> getWord16  -- ECParameters NamedCurve
            case mgrp of
              Nothing -> error "getServerECDHParams: unknown group"
              Just grp -> do
                  mxy <- getOpaque8 -- ECPoint
                  case decodeGroupPublic grp mxy of
                    Left e       -> error $ "getServerECDHParams: " ++ show e
                    Right grppub -> return $ ServerECDHParams grp grppub
        _ ->
            error "getServerECDHParams: unknown type for ECDH Params"

-- RFC 4492 Section 5.4 Server Key Exchange
putServerECDHParams :: ServerECDHParams -> Put
putServerECDHParams (ServerECDHParams grp grppub) = ETT__.t "Network.TLS.Packet.putServerECDHParams" ETT__.$ do
    putWord8 3                            -- ECParameters ECCurveType
    putWord16 $ fromEnumSafe16 grp        -- ECParameters NamedCurve
    putOpaque8 $ encodeGroupPublic grppub -- ECPoint

getDigitallySigned :: Version -> Get DigitallySigned
getDigitallySigned ver
    | ver >= TLS12 = ETT__.t "Network.TLS.Packet.getDigitallySigned" ETT__.$ DigitallySigned <$> (Just <$> getSignatureHashAlgorithm)
                                     <*> getOpaque16
    | otherwise    = ETT__.t "Network.TLS.Packet.getDigitallySigned" ETT__.$ DigitallySigned Nothing <$> getOpaque16

putDigitallySigned :: DigitallySigned -> Put
putDigitallySigned (DigitallySigned mhash sig) = ETT__.t "Network.TLS.Packet.putDigitallySigned" ETT__.$
    maybe (return ()) putSignatureHashAlgorithm mhash >> putOpaque16 sig

{-
 - decode and encode ALERT
 -}

decodeChangeCipherSpec :: ByteString -> Either TLSError ()
decodeChangeCipherSpec = ETT__.t "Network.TLS.Packet.decodeChangeCipherSpec" ETT__.$ runGetErr "changecipherspec" $ do
    x <- getWord8
    when (x /= 1) (fail "unknown change cipher spec content")

encodeChangeCipherSpec :: ByteString
encodeChangeCipherSpec = ETT__.t "Network.TLS.Packet.encodeChangeCipherSpec" ETT__.$ runPut (putWord8 1)

-- rsa pre master secret
decodePreMasterSecret :: ByteString -> Either TLSError (Version, ByteString)
decodePreMasterSecret = ETT__.t "Network.TLS.Packet.decodePreMasterSecret" ETT__.$ runGetErr "pre-master-secret" $
    (,) <$> getVersion <*> getBytes 46

encodePreMasterSecret :: Version -> ByteString -> ByteString
encodePreMasterSecret version bytes = ETT__.t "Network.TLS.Packet.encodePreMasterSecret" ETT__.$ runPut (putBinaryVersion version >> putBytes bytes)

-- | in certain cases, we haven't manage to decode ServerKeyExchange properly,
-- because the decoding was too eager and the cipher wasn't been set yet.
-- we keep the Server Key Exchange in it unparsed format, and this function is
-- able to really decode the server key xchange if it's unparsed.
decodeReallyServerKeyXchgAlgorithmData :: Version
                                       -> CipherKeyExchangeType
                                       -> ByteString
                                       -> Either TLSError ServerKeyXchgAlgorithmData
decodeReallyServerKeyXchgAlgorithmData ver cke = ETT__.t "Network.TLS.Packet.decodeReallyServerKeyXchgAlgorithmData" ETT__.$
    runGetErr "server-key-xchg-algorithm-data" (decodeServerKeyXchgAlgorithmData ver cke)


{-
 - generate things for packet content
 -}
type PRF = ByteString -> ByteString -> Int -> ByteString

-- | The TLS12 PRF is cipher specific, and some TLS12 algorithms use SHA384
-- instead of the default SHA256.
getPRF :: Version -> Cipher -> PRF
getPRF ver ciph
    | ver < TLS12 = ETT__.t "Network.TLS.Packet.getPRF" ETT__.$ prf_MD5SHA1
    | maybe True (< TLS12) (cipherMinVer ciph) = ETT__.t "Network.TLS.Packet.getPRF" ETT__.$ prf_SHA256
    | otherwise = ETT__.t "Network.TLS.Packet.getPRF" ETT__.$ prf_TLS ver $ fromMaybe SHA256 $ cipherPRFHash ciph

generateMasterSecret_SSL :: ByteArrayAccess preMaster => preMaster -> ClientRandom -> ServerRandom -> ByteString
generateMasterSecret_SSL premasterSecret (ClientRandom c) (ServerRandom s) = ETT__.t "Network.TLS.Packet.generateMasterSecret_SSL" ETT__.$
    B.concat $ map computeMD5 ["A","BB","CCC"]
  where computeMD5  label = hash MD5 $ B.concat [ B.convert premasterSecret, computeSHA1 label ]
        computeSHA1 label = hash SHA1 $ B.concat [ label, B.convert premasterSecret, c, s ]

generateMasterSecret_TLS :: ByteArrayAccess preMaster => PRF -> preMaster -> ClientRandom -> ServerRandom -> ByteString
generateMasterSecret_TLS prf premasterSecret (ClientRandom c) (ServerRandom s) = ETT__.t "Network.TLS.Packet.generateMasterSecret_TLS" ETT__.$
    prf (B.convert premasterSecret) seed 48
  where seed = B.concat [ "master secret", c, s ]

generateMasterSecret :: ByteArrayAccess preMaster
                     => Version
                     -> Cipher
                     -> preMaster
                     -> ClientRandom
                     -> ServerRandom
                     -> ByteString
generateMasterSecret SSL2 _ = ETT__.t "Network.TLS.Packet.generateMasterSecret" ETT__.$ generateMasterSecret_SSL
generateMasterSecret SSL3 _ = ETT__.t "Network.TLS.Packet.generateMasterSecret" ETT__.$ generateMasterSecret_SSL
generateMasterSecret v    c = ETT__.t "Network.TLS.Packet.generateMasterSecret" ETT__.$ generateMasterSecret_TLS $ getPRF v c

generateExtendedMasterSec :: ByteArrayAccess preMaster
                          => Version
                          -> Cipher
                          -> preMaster
                          -> ByteString
                          -> ByteString
generateExtendedMasterSec v c premasterSecret sessionHash = ETT__.t "Network.TLS.Packet.generateExtendedMasterSec" ETT__.$
    getPRF v c (B.convert premasterSecret) seed 48
  where seed = B.append "extended master secret" sessionHash

generateKeyBlock_TLS :: PRF -> ClientRandom -> ServerRandom -> ByteString -> Int -> ByteString
generateKeyBlock_TLS prf (ClientRandom c) (ServerRandom s) mastersecret kbsize = ETT__.t "Network.TLS.Packet.generateKeyBlock_TLS" ETT__.$
    prf mastersecret seed kbsize where seed = B.concat [ "key expansion", s, c ]

generateKeyBlock_SSL :: ClientRandom -> ServerRandom -> ByteString -> Int -> ByteString
generateKeyBlock_SSL (ClientRandom c) (ServerRandom s) mastersecret kbsize = ETT__.t "Network.TLS.Packet.generateKeyBlock_SSL" ETT__.$
    B.concat $ map computeMD5 $ take ((kbsize `div` 16) + 1) labels
  where labels            = [ uncurry BC.replicate x | x <- zip [1..] ['A'..'Z'] ]
        computeMD5  label = hash MD5 $ B.concat [ mastersecret, computeSHA1 label ]
        computeSHA1 label = hash SHA1 $ B.concat [ label, mastersecret, s, c ]

generateKeyBlock :: Version
                 -> Cipher
                 -> ClientRandom
                 -> ServerRandom
                 -> ByteString
                 -> Int
                 -> ByteString
generateKeyBlock SSL2 _ = ETT__.t "Network.TLS.Packet.generateKeyBlock" ETT__.$ generateKeyBlock_SSL
generateKeyBlock SSL3 _ = ETT__.t "Network.TLS.Packet.generateKeyBlock" ETT__.$ generateKeyBlock_SSL
generateKeyBlock v    c = ETT__.t "Network.TLS.Packet.generateKeyBlock" ETT__.$ generateKeyBlock_TLS $ getPRF v c

generateFinished_TLS :: PRF -> ByteString -> ByteString -> HashCtx -> ByteString
generateFinished_TLS prf label mastersecret hashctx = ETT__.t "Network.TLS.Packet.generateFinished_TLS" ETT__.$ prf mastersecret seed 12
  where seed = B.concat [ label, hashFinal hashctx ]

generateFinished_SSL :: ByteString -> ByteString -> HashCtx -> ByteString
generateFinished_SSL sender mastersecret hashctx = ETT__.t "Network.TLS.Packet.generateFinished_SSL" ETT__.$ B.concat [md5hash, sha1hash]
  where md5hash  = hash MD5 $ B.concat [ mastersecret, pad2, md5left ]
        sha1hash = hash SHA1 $ B.concat [ mastersecret, B.take 40 pad2, sha1left ]

        lefthash = hashFinal $ flip hashUpdateSSL (pad1, B.take 40 pad1)
                             $ foldl hashUpdate hashctx [sender,mastersecret]
        (md5left,sha1left) = B.splitAt 16 lefthash
        pad2     = B.replicate 48 0x5c
        pad1     = B.replicate 48 0x36

generateClientFinished :: Version
                       -> Cipher
                       -> ByteString
                       -> HashCtx
                       -> ByteString
generateClientFinished ver ciph
    | ver < TLS10 = ETT__.t "Network.TLS.Packet.generateClientFinished" ETT__.$ generateFinished_SSL "CLNT"
    | otherwise   = ETT__.t "Network.TLS.Packet.generateClientFinished" ETT__.$ generateFinished_TLS (getPRF ver ciph) "client finished"

generateServerFinished :: Version
                       -> Cipher
                       -> ByteString
                       -> HashCtx
                       -> ByteString
generateServerFinished ver ciph
    | ver < TLS10 = ETT__.t "Network.TLS.Packet.generateServerFinished" ETT__.$ generateFinished_SSL "SRVR"
    | otherwise   = ETT__.t "Network.TLS.Packet.generateServerFinished" ETT__.$ generateFinished_TLS (getPRF ver ciph) "server finished"

{- returns *output* after final MD5/SHA1 -}
generateCertificateVerify_SSL :: ByteString -> HashCtx -> ByteString
generateCertificateVerify_SSL = ETT__.t "Network.TLS.Packet.generateCertificateVerify_SSL" ETT__.$ generateFinished_SSL ""

{- returns *input* before final SHA1 -}
generateCertificateVerify_SSL_DSS :: ByteString -> HashCtx -> ByteString
generateCertificateVerify_SSL_DSS mastersecret hashctx = ETT__.t "Network.TLS.Packet.generateCertificateVerify_SSL_DSS" ETT__.$ toHash
  where toHash = B.concat [ mastersecret, pad2, sha1left ]

        sha1left = hashFinal $ flip hashUpdate pad1
                             $ hashUpdate hashctx mastersecret
        pad2     = B.replicate 40 0x5c
        pad1     = B.replicate 40 0x36

encodeSignedDHParams :: ServerDHParams -> ClientRandom -> ServerRandom -> ByteString
encodeSignedDHParams dhparams cran sran = ETT__.t "Network.TLS.Packet.encodeSignedDHParams" ETT__.$ runPut $
    putClientRandom32 cran >> putServerRandom32 sran >> putServerDHParams dhparams

-- Combination of RFC 5246 and 4492 is ambiguous.
-- Let's assume ecdhe_rsa and ecdhe_dss are identical to
-- dhe_rsa and dhe_dss.
encodeSignedECDHParams :: ServerECDHParams -> ClientRandom -> ServerRandom -> ByteString
encodeSignedECDHParams dhparams cran sran = ETT__.t "Network.TLS.Packet.encodeSignedECDHParams" ETT__.$ runPut $
    putClientRandom32 cran >> putServerRandom32 sran >> putServerECDHParams dhparams

fromJustM :: MonadFail m => String -> Maybe a -> m a
fromJustM what Nothing  = ETT__.tm "Network.TLS.Packet.fromJustM" ETT__.$ fail ("fromJustM " ++ what ++ ": Nothing")
fromJustM _    (Just x) = ETT__.tm "Network.TLS.Packet.fromJustM" ETT__.$ return x
