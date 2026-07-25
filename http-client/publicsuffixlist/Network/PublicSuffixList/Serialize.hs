module Network.PublicSuffixList.Serialize (getDataStructure, putDataStructure) where

import           Blaze.ByteString.Builder           (Builder, fromWord8,
                                                     toByteString)
import           Blaze.ByteString.Builder.Char.Utf8 (fromText)
import qualified Data.ByteString                    as BS
import           Data.Foldable                      (foldMap)
import           Data.Map                           (Map)
import qualified Data.Map                           as Map
import           Data.Monoid                        (mappend)
import qualified Data.Text                          as T
import qualified Data.Text.Encoding                 as TE

import           Network.PublicSuffixList.Types
import qualified Debug.EulerTrace.HttpClient as ETT__

getTree :: BS.ByteString -> (Tree T.Text, BS.ByteString)
getTree = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.getTree" ETT__.$
    loop Map.empty
  where
    loop m bs
        | BS.null bs = (Node m, bs)
        | BS.head bs == 0 = (Node m, BS.drop 1 bs)
        | otherwise =
            let (k, v, bs') = getPair bs
             in loop (Map.insert k v m) bs'

getPair :: BS.ByteString -> (T.Text, Tree T.Text, BS.ByteString)
getPair bs0 = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.getPair" ETT__.$
    (k, v, bs2)
  where
    (k, bs1) = getText bs0
    (v, bs2) = getTree bs1

getText :: BS.ByteString -> (T.Text, BS.ByteString)
getText bs0 = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.getText" ETT__.$
    (TE.decodeUtf8 v, BS.drop 1 bs1)
  where
    (v, bs1) = BS.break (== 0) bs0

getDataStructure :: BS.ByteString -> DataStructure
getDataStructure bs0 = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.getDataStructure" ETT__.$
    (x, y)
  where
    (x, bs1) = getTree bs0
    (y, _) = getTree bs1

putTree :: Tree T.Text -> Builder
putTree = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.putTree" ETT__.$ putMap . children

putMap :: Map T.Text (Tree T.Text) -> Builder
putMap m = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.putMap" ETT__.$ Data.Foldable.foldMap putPair (Map.toList m) `mappend` fromWord8 0

putPair :: (T.Text, Tree T.Text) -> Builder
putPair (x, y) = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.putPair" ETT__.$ putText x `mappend` putTree y

putText :: T.Text -> Builder
putText t = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.putText" ETT__.$ fromText t `Data.Monoid.mappend` fromWord8 0

putDataStructure :: DataStructure -> BS.ByteString
putDataStructure (x, y) = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Serialize.putDataStructure" ETT__.$ toByteString $ putTree x `mappend` putTree y

