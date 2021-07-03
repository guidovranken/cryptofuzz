# secp256k1

## Library compilation

```sh
git clone --depth 1 https://github.com/bitcoin-core/secp256k1.git
cd secp256k1/
autoreconf -ivf
./configure --enable-static --disable-tests --disable-benchmark --with-bignum=no --disable-exhaustive-tests --enable-module-recovery --enable-module-schnorrsig --enable-experimental --enable-module-ecdh
make
export SECP256K1_INCLUDE_PATH=$(realpath .)
export LIBSECP256K1_A_PATH=$(realpath .libs/libsecp256k1.a)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_SECP256K1"
```
