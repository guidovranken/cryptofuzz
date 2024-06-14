# Mbed TLS

The `mbedtls` module is a crypto implementation using Mbed TLS's classic crypto interface.
See the `tf-psa-crypto` module for the newer PSA Crypto interface.

You can use the same build of Mbed TLS (`libmbedcrypto.a`) for both.

## Library compilation

```sh
git clone --depth 1 --recurse-submodules -b mbedtls-3.6 https://github.com/Mbed-TLS/mbedtls.git
cd mbedtls/
python3 -m venv venv
source venv/bin/activate
pip install -r scripts/basic.requirements.txt
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
