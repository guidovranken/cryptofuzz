# mbedTLS

## Library compilation

```sh
git clone --depth 1 https://github.com/ARMmbed/mbedtls.git
cd mbedtls/
scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
scripts/config.pl set MBEDTLS_CMAC_C
scripts/config.pl set MBEDTLS_NIST_KW_C
scripts/config.pl set MBEDTLS_ARIA_C
scripts/config.pl set MBEDTLS_MD2_C
scripts/config.pl set MBEDTLS_MD4_C
mkdir build/
cd build/
cmake .. -DENABLE_PROGRAMS=0 -DENABLE_TESTING=0
make -j$(nproc)
export MBEDTLS_LIBMBEDCRYPTO_A_PATH=$(realpath library/libmbedcrypto.a)
export MBEDTLS_INCLUDE_PATH=$(realpath ../include)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_MBEDTLS"
```

If you want to compile without assembly language optimizations, run these commands from the ```mbedtls/``` directory as well before running cmake:

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
