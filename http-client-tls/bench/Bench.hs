{-# LANGUAGE CPP #-}
module Main where

#if MIN_VERSION_gauge(0, 2, 0)
import Gauge
#else
import Gauge.Main
#endif
import Network.HTTP.Client
import Network.HTTP.Client.TLS
import qualified Debug.EulerTrace.HttpClientTls as ETT__

main :: IO ()
main = ETT__.tio "bench.Bench.main" ETT__.$ defaultMain [
      bgroup "newManager" [
            bench "defaultManagerSettings" $
                whnfIO (newManager defaultManagerSettings)
          , bench "tlsManagerSettings" $
                whnfIO (newManager tlsManagerSettings)
          ]
    ]
