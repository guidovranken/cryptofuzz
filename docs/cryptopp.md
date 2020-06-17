# Crypto++

## Library compilation

```sh
git clone --depth 1 https://github.com/weidai11/cryptopp/
cd cryptopp/
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_CRYPTOPP"
export LIBCRYPTOPP_A_PATH=`realpath libcryptopp.a`
export CRYPTOPP_INCLUDE_PATH=`realpath .`
```

## Module compilation

```sh
cd cryptofuzz/modules/cryptopp/
make
```
