# wolfCrypt

## Library compilation

### Normal math

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_SP_INT_NEGATIVE"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
git clone --depth 1 https://github.com/wolfSSL/wolfsm
cd wolfsm/
./install.sh
cd ../wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-aesgcm-stream --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --enable-shake128 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-siphash --enable-cryptocb --enable-eccencrypt --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-eccsi --with-eccminsz=0 --enable-dsa --enable-sm2 --enable-sm3 --enable-sm4-cbc --enable-sm4-ccm --enable-sm4-ctr --enable-sm4-ecb --enable-sm4-gcm
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

### Fastmath

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
git clone --depth 1 https://github.com/wolfSSL/wolfsm
cd wolfsm/
./install.sh
cd ../wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-aesgcm-stream --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --enable-shake128 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-siphash --enable-cryptocb --enable-eccencrypt --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-eccsi --enable-fastmath --with-eccminsz=0 --enable-dsa --enable-sm2 --enable-sm3 --enable-sm4-cbc --enable-sm4-ccm --enable-sm4-ctr --enable-sm4-ecb --enable-sm4-gcm
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

### Heapmath

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_SP_INT_NEGATIVE"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
git clone --depth 1 https://github.com/wolfSSL/wolfsm
cd wolfsm/
./install.sh
cd ../wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-aesgcm-stream --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --enable-shake128 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-siphash --enable-cryptocb --enable-eccencrypt --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-eccsi --enable-heapmath --with-eccminsz=0 --enable-dsa --enable-sm2 --enable-sm3 --enable-sm4-cbc --enable-sm4-ccm --enable-sm4-ctr --enable-sm4-ecb --enable-sm4-gcm
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

### sp-math all

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_SP_INT_NEGATIVE"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
git clone --depth 1 https://github.com/wolfSSL/wolfsm
cd wolfsm/
./install.sh
cd ../wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-aesgcm-stream --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --enable-shake128 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-siphash --enable-cryptocb --enable-eccencrypt --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-eccsi --enable-sp-math-all --with-eccminsz=0 --enable-dsa --enable-sm2 --enable-sm3 --enable-sm4-cbc --enable-sm4-ccm --enable-sm4-ctr --enable-sm4-ecb --enable-sm4-gcm
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

### sp-math all 8 bit

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DSP_WORD_SIZE=8 -DWOLFSSL_SP_INT_NEGATIVE"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
git clone --depth 1 https://github.com/wolfSSL/wolfsm
cd wolfsm/
./install.sh
cd ../wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-aesgcm-stream --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --enable-shake128 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-siphash --enable-cryptocb --enable-eccencrypt --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-eccsi --enable-sp-math-all --with-eccminsz=0 --enable-dsa --enable-sm2 --enable-sm3 --enable-sm4-cbc --enable-sm4-ccm --enable-sm4-ctr --enable-sm4-ecb --enable-sm4-gcm
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

### SP math

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP -DWOLFSSL_PUBLIC_ECC_ADD_DBL"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
git clone --depth 1 https://github.com/wolfSSL/wolfsm
cd wolfsm/
./install.sh
cd ../wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-aesgcm-stream --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --enable-shake128 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-xchacha --enable-siphash --enable-cryptocb --enable-eccencrypt --enable-smallstack --enable-ed25519-stream --enable-ed448-stream --enable-eccsi --enable-sp --enable-sp-math --with-eccminsz=0
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

# OpenSSL API

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K -DWOLFSSL_ECDSA_SET_K_ONE_LOOP"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
git clone --depth 1 https://github.com/wolfSSL/wolfsm
cd wolfsm/
./install.sh
cd ../wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-aesccm --enable-aesctr --enable-xts --enable-des3 --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-aessiv --enable-aesgcm-stream --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --enable-shake128 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha --enable-siphash --enable-cryptocb --enable-eccencrypt --enable-ed25519-stream --enable-ed448-stream --enable-smallstack --enable-opensslall --enable-opensslextra --with-eccminsz=0 --enable-dsa --enable-sm2 --enable-sm3 --enable-sm4-cbc --enable-sm4-ccm --enable-sm4-ctr --enable-sm4-ecb --enable-sm4-gcm
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_WOLFCRYPT_OPENSSL"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

## Module compilation

```sh
cd cryptofuzz/modules/wolfcrypt/
make
```
