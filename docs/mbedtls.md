# mbedTLS

## Library compilation

```sh
git clone --depth 1 https://github.com/ARMmbed/mbed-crypto.git
cd mbed-crypto/
scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
mkdir build/
cd build/
cmake .. -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make
export MBEDTLS_LIBMBEDCRYPTO_A_PATH=`realpath library/libmbedcrypto.a`
export MBEDTLS_INCLUDE_PATH=`realpath ../include`
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MBEDTLS"
```

If you want to compile without assembly language optimizations, run these commands from the ```mbed-crypto/``` directory as well before running cmake:

```sh
scripts/config.pl unset MBEDTLS_HAVE_ASM
scripts/config.pl unset MBEDTLS_PADLOCK_C
scripts/config.pl unset MBEDTLS_AESNI_C
```

## Module compilation

```sh
cd cryptofuzz/modules/mbedtls/
make
```
