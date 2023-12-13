# Mbed TLS

The `mbedtls` module is a crypto implementation using Mbed TLS's classic crypto interface.

## Library compilation

```sh
git clone --depth 1 -b development https://github.com/Mbed-TLS/mbedtls.git
cd mbedtls/
scripts/config.py set MBEDTLS_PLATFORM_MEMORY
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
scripts/config.py unset MBEDTLS_HAVE_ASM
scripts/config.py unset MBEDTLS_PADLOCK_C
scripts/config.py unset MBEDTLS_AESNI_C
scripts/config.py unset MBEDTLS_AESCE_C
```

## Module compilation

```sh
cd cryptofuzz/modules/mbedtls/
make
```
