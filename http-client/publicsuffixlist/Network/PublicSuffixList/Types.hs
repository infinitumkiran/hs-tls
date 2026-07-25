{-|
This module is only exported for the use of the 'publicsuffixlistcreate' package.
Every one else should consider everything in this file to be opaque.
-}

module Network.PublicSuffixList.Types where

import qualified Data.Map             as M
import qualified Data.Text            as T
import qualified Debug.EulerTrace.HttpClient as ETT__

newtype Tree e = Node { children :: M.Map e (Tree e) }
  deriving (Show, Eq)

def :: Ord e => Tree e
def = ETT__.t "publicsuffixlist.Network.PublicSuffixList.Types.def" ETT__.$ Node M.empty

type DataStructure = (Tree T.Text, Tree T.Text)
