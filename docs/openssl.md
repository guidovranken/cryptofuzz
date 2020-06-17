# OpenSSL, LibreSSL, BoringSSL

## Library compilation

### OpenSSL master, 1.1.0, 1.0.2

```sh
git clone --depth 1 https://github.com/openssl/openssl.git
cd openssl/
./config enable-md2 enable-rc5
make -j$(nproc)
export OPENSSL_INCLUDE_PATH=`realpath include/`
export OPENSSL_LIBCRYPTO_A_PATH=`realpath libcrypto.a`
```

Add the parameter ```no-asm``` to the ```./config``` command to build without assembly language optimizations.

If you're using OpenSSL 1.1.0, also run:

```sh
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_OPENSSL_110"
```

If you're using OpenSSL 1.0.2, also run:

```sh
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_OPENSSL_102"
```

### LibreSSL

```sh
git clone --depth 1 https://github.com/libressl-portable/portable libressl
cd libressl
./update.sh
mkdir build/
cd build/
cmake -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" ..
make crypto -j$(nproc)
cd ../
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_LIBRESSL"
export OPENSSL_INCLUDE_PATH=`realpath include/`
export OPENSSL_LIBCRYPTO_A_PATH=`realpath build/crypto/libcrypto.a`
```

### BoringSSL

```sh
git clone --depth 1 https://boringssl.googlesource.com/boringssl
cd boringssl/
mkdir build/
cd build/
cmake -DCMAKE_CXX_FLAGS="$CXXFLAGS" -DCMAKE_C_FLAGS="$CFLAGS" -DBORINGSSL_ALLOW_CXX_RUNTIME=1 ..
make crypto -j$(nproc)
cd ../
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_BORINGSSL"
export OPENSSL_INCLUDE_PATH=`realpath include/`
export OPENSSL_LIBCRYPTO_A_PATH=`realpath build/crypto/libcrypto.a`
```

Add the parameter ```-DOPENSSL_NO_ASM=1``` to the ```cmake``` command to build without assembly language optimizations.

## Module compilation

```sh
cd cryptofuzz/modules/openssl/
make
```

## Notes

Only one distict OpenSSL branch or derivative can be used at the same time.

It is also possible to not use OpenSSL (or derivates):

```sh
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL
```
