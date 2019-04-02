#!/bin/bash

export CRYPTOFUZZ_PATH=`realpath .`

export CC=clang
export CXX=clang++
export CFLAGS="-fsanitize=fuzzer-no-link,address,undefined -fno-common -g -O3 -I $CRYPTOFUZZ_PATH/fuzzing-headers/include"
export CXXFLAGS="$CFLAGS"
export LIBFUZZER_LINK="-fsanitize=fuzzer"

rm -rf $CRYPTOFUZZ_PATH/external
mkdir -p $CRYPTOFUZZ_PATH/external

# OpenSSL
    rm -rf $CRYPTOFUZZ_PATH/external/openssl
    git clone --depth 1 https://github.com/openssl/openssl $CRYPTOFUZZ_PATH/external/openssl
    cd $CRYPTOFUZZ_PATH/external/openssl
    ./config --debug enable-md2 enable-rc5
    make -j$(nproc)

    cd $CRYPTOFUZZ_PATH/modules/openssl
    OPENSSL_INCLUDE_PATH="$CRYPTOFUZZ_PATH/external/openssl/include" OPENSSL_LIBCRYPTO_A_PATH="$CRYPTOFUZZ_PATH/external/openssl/libcrypto.a" make -B

## mbed TLS
    rm -rf $CRYPTOFUZZ_PATH/external/mbedtls
    git clone --depth 1 https://github.com/ARMmbed/mbedtls $CRYPTOFUZZ_PATH/external/mbedtls
    cd $CRYPTOFUZZ_PATH/external/mbedtls
    CFLAGS="$CFLAGS -DMBEDTLS_CMAC_C" make lib -j$(nproc)

    cd $CRYPTOFUZZ_PATH/modules/mbedtls
    MBEDTLS_INCLUDE_PATH="$CRYPTOFUZZ_PATH/external/mbedtls/include" MBEDTLS_LIBMBEDCRYPTO_A_PATH="$CRYPTOFUZZ_PATH/external/mbedtls/library/libmbedcrypto.a" make -B

## Monero
    cd $CRYPTOFUZZ_PATH/modules/monero
    bash getfiles.sh
    make -B

# Public domain
    cd $CRYPTOFUZZ_PATH/modules/publicdomain
    make -B

# cppcrypto
    rm -rf $CRYPTOFUZZ_PATH/external/cppcrypto
    mkdir $CRYPTOFUZZ_PATH/external/cppcrypto
    cd $CRYPTOFUZZ_PATH/external/cppcrypto
    wget https://netix.dl.sourceforge.net/project/cppcrypto/cppcrypto-0.17-src.zip
    unzip cppcrypto-0.17-src.zip
    cd cppcrypto

    cp $CRYPTOFUZZ_PATH/patches/cppcrypto/Makefile .

    make -j$(nproc)

    cd $CRYPTOFUZZ_PATH/modules/cppcrypto
    CPPCRYPTO_INCLUDE_PATH="$CRYPTOFUZZ_PATH/external/cppcrypto" CPPCRYPTO_LIBCPPCRYPTO_A_PATH="$CRYPTOFUZZ_PATH/external/cppcrypto/cppcrypto/libcppcrypto.a" make -B


cd $CRYPTOFUZZ_PATH
export CRYPTOFUZZ_CXX_FLAGS="$CXXFLAGS"
export CRYPTOFUZZ_CXX_FLAGS="$CRYPTOFUZZ_CXX_FLAGS -I $CRYPTOFUZZ_PATH/external/openssl/include"
export CRYPTOFUZZ_CXX_FLAGS="$CRYPTOFUZZ_CXX_FLAGS -DCRYPTOFUZZ_MBEDTLS -I $CRYPTOFUZZ_PATH/external/mbedtls/include"
export CRYPTOFUZZ_CXX_FLAGS="$CRYPTOFUZZ_CXX_FLAGS -DCRYPTOFUZZ_MONERO"
export CRYPTOFUZZ_CXX_FLAGS="$CRYPTOFUZZ_CXX_FLAGS -DCRYPTOFUZZ_PUBLICDOMAIN"
export CRYPTOFUZZ_CXX_FLAGS="$CRYPTOFUZZ_CXX_FLAGS -DCRYPTOFUZZ_CPPCRYPTO -I $CRYPTOFUZZ_PATH/external/cppcrypto"

export CRYPTOFUZZ_MODULE_PATHS="modules/openssl/module.a modules/mbedtls/module.a modules/monero/module.a modules/publicdomain/module.a modules/cppcrypto/module.a"
CXXFLAGS="$CRYPTOFUZZ_CXX_FLAGS" make -B -j$(nproc)
