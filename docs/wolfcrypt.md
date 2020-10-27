# wolfCrypt

## Library compilation

```sh
export CFLAGS="$CFLAGS -DHAVE_AES_ECB -DWOLFSSL_DES_ECB -DHAVE_ECC_SECPR2 -DHAVE_ECC_SECPR3 -DHAVE_ECC_BRAINPOOL -DHAVE_ECC_KOBLITZ -DWOLFSSL_ECDSA_SET_K"
git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
cd wolfssl/
autoreconf -ivf
./configure --enable-static --enable-md2 --enable-md4 --enable-ripemd --enable-blake2 --enable-blake2s --enable-pwdbased --enable-scrypt --enable-hkdf --enable-cmac --enable-arc4 --enable-camellia --enable-rabbit --enable-aesccm --enable-aesctr --enable-hc128 --enable-xts --enable-des3 --enable-idea --enable-x963kdf --enable-harden --enable-aescfb --enable-aesofb --enable-aeskeywrap --enable-keygen --enable-curve25519 --enable-curve448 --enable-shake256 --disable-crypttests --disable-examples --enable-compkey --enable-ed448 --enable-ed25519 --enable-ecccustcurves --enable-xchacha
make -j$(nproc)
export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_WOLFCRYPT"
export WOLFCRYPT_LIBWOLFSSL_A_PATH=`realpath src/.libs/libwolfssl.a`
export WOLFCRYPT_INCLUDE_PATH=`realpath .`
```

## Module compilation

```sh
cd cryptofuzz/modules/wolfcrypt/
make
```
