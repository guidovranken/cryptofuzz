# Cryptofuzz - Differential cryptography fuzzing

## Documentation

Documentation on how to implement modules and use Cryptofuzz will follow.

## Hall of Fame

- OpenSSL: [ARIA GCM ciphers memory leak after EVP_CTRL_AEAD_SET_IVLEN](https://github.com/openssl/openssl/issues/8567)
- OpenSSL: [HMAC with SHAKE128 via EVP interface crashes on EVP_DigestSignUpdate](https://github.com/openssl/openssl/issues/8563)
- OpenSSL: [BLAKE2b_Update can pass NULL to memcpy (undefined behavior)](https://github.com/openssl/openssl/issues/8576)
- LibreSSL: [EVP_aes_128_cbc_hmac_sha1, EVP_aes_256_cbc_hmac_sha1 decrypt OOB read/crash/invalid result](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libcrypto/evp/e_aes_cbc_hmac_sha1.c?rev=1.15&content-type=text/x-cvsweb-markup)
- OpenSSL: [CHACHA20_POLY1305 different results for chunked/non-chunked updating](https://github.com/openssl/openssl/issues/8675)
- OpenSSL: [OpenSSL 1.0.2: BIO_read + *_WRAP ciphers copy to uninitialized pointer](https://github.com/openssl/openssl/issues/8688)
- BoringSSL: [AEAD AES GCM SIV NULL pointer dereference/OOB read](https://boringssl-review.googlesource.com/c/boringssl/+/35545)
- LibreSSL: [BIO_read can report more bytes written than buffer can hold](https://cvsweb.openbsd.org/src/lib/libcrypto/bio/bio_lib.c?rev=1.29&content-type=text/x-cvsweb-markup)
- LibreSSL: [Use-after-free/bad free after EVP_CIPHER_CTX_copy](https://cvsweb.openbsd.org/src/lib/libcrypto/evp/evp_enc.c?rev=1.41&content-type=text/x-cvsweb-markup)
- BoringSSL: [Use-after-free/bad free after EVP_CIPHER_CTX_copy](https://boringssl.googlesource.com/boringssl/+/65dc45cb57c7c6900a0657f6ee5c00fce9d366f5)
- LibreSSL: [GOST HMAC uses and outputs uninitialized memory](https://cvsweb.openbsd.org/src/lib/libcrypto/evp/digest.c?rev=1.31&content-type=text/x-cvsweb-markup)
- OpenSSL: [Overlong tag buffer leaves memory uninitialized in CCM mode](https://github.com/openssl/openssl/pull/8810)
- OpenSSL: [Buffer write overflow when passing large RC5 key](https://github.com/openssl/openssl/pull/8834)
- OpenSSL: [Hang after particular sequence of operations](https://github.com/openssl/openssl/issues/8827)
- LibreSSL: [Overlong tag buffer leaves memory uninitialized in CCM mode](https://cvsweb.openbsd.org/src/lib/libcrypto/modes/ccm128.c?rev=1.5&content-type=text/x-cvsweb-markup)
- LibreSSL: [AES GCM context copy crash](https://cvsweb.openbsd.org/src/lib/libcrypto/evp/e_aes.c?rev=1.38&content-type=text/x-cvsweb-markup)
- LibreSSL: [Streebog wrong output](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libcrypto/gost/streebog.c?rev=1.6&content-type=text/x-cvsweb-markup)
- OpenSSL: [EVP_EncryptUpdate, EVP_EncryptFinal_ex branching on uninitialized memory](https://github.com/openssl/openssl/pull/8874)
- libgcrypt: [Invalid output of MD4, MD5, RIPEMD160](https://lists.gnupg.org/pipermail/gcrypt-devel/2019-May/004712.html)
- OpenSSL: RC5 signed integer overflow, TBA
- LibreSSL: [AES CCM context copy crash](https://cvsweb.openbsd.org/src/lib/libcrypto/evp/e_aes.c?rev=1.39&content-type=text/x-cvsweb-markup)
- LibreSSL: [DES EDE3 CFB1 leaves output uninitialized](https://cvsweb.openbsd.org/src/lib/libcrypto/evp/e_des3.c?rev=1.20&content-type=text/x-cvsweb-markup)
