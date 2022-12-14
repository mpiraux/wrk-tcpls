# WRK-MultiProtocol

  **a TCP/HTTP & QUIC/HTTP benchmarking tool based on wrk and wrk2**
  
  On top of the new QUIC support, WRK-MP still fully supports WRK1/2 features, with even some improvements.

  This repository is a modified version of WRK2 [http://github.com/gilene/wrk2](wrk2) with support for QUIC and various small improvements

  QUIC support is now limited to HTTP 0.9 over QUIC, made to work against PicoQUIC HTTP server (using the hq ALPN). It also only supports disabled keep-alive for now.

  The QUIC support is built using the picoquic library. Refer to picoquic for installation. To enable QUIC support, you must use the -q flag. Except for that most wrk2 documentation applies. We just changed a bit the default behavior, so if you omit the rate (or give -R -1) WRK will behave like the original version, trying to push as many request as possible.

## Building

```
./autogen.sh
./configure
make
sudo make install
```
