# Cryptofuzz - Differential cryptography fuzzing

[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/cryptofuzz.svg)](https://oss-fuzz.com/coverage-report/job/libfuzzer_asan_cryptofuzz/latest)

## Documentation

For building Cryptofuzz, please refer to [`docs/building.md`](docs/building.md).

For instructions on how to run Cryptofuzz, please see [`docs/running.md`](docs/running.md).

## Bugs found by Cryptofuzz

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
- Crypto++: [Scrypt crash with blocksize 0](https://github.com/weidai11/cryptopp/commit/e0b60439bf63b02ed93bc2c5b4ed15125fd6f278)
- EverCrypt: Illegal instruction exception on non-AVX CPUs
- OpenSSL: [OpenSSL 1.0.2: RC4 OOB read](https://github.com/openssl/openssl/issues/8972)
- OpenSSL: [OpenSSL 1.0.2: Branch on uninitialized memory in EVP_CIPHER_CTX_copy](https://github.com/openssl/openssl/issues/8980)
- Crypto++: [PBKDF1 OOB read](https://github.com/weidai11/cryptopp/issues/874)
- NSS: [MD2 invalid output](https://bugzilla.mozilla.org/show_bug.cgi?id=1575923)
- Botan: [CAST5_CBC invalid output](https://github.com/randombit/botan/issues/2081)
- Botan: [Streebog invalid output](https://github.com/randombit/botan/issues/2082)
- Botan: [PBKDF2 hang (very long loop) if iterations == 0](https://github.com/randombit/botan/issues/2088)
- NSS: [HKDF SHA1 stack buffer overflow, CVE-2019-11759](https://hg.mozilla.org/projects/nss/rev/c0913ad7a5609751a8dfc37ae2e0a7a0cd6a42dd)
- NSS: [RC2 CBC OOB read with undersized IV](https://hg.mozilla.org/projects/nss/rev/53d92a32408049038f450aa747b0030607988230)
- NSS: [SEED_CBC encryption out-of-bounds write](https://hg.mozilla.org/projects/nss/rev/7580a5a212c78ab21fc4878330dd7872c3b530b8)
- NSS: [CKM_AES_GCM succeeds with invalid tag sizes, risk of memory corruption](https://hg.mozilla.org/projects/nss/rev/4e3971fd992c0513d0696048c64b7230e5b6039b)
- NSS: [PBKDF2 memory leak if key size > 256](https://bugzilla.mozilla.org/show_bug.cgi?id=1591363)
- NSS: [DES IV buffer overread if IV is undersized](https://hg.mozilla.org/projects/nss/rev/35857ae98190c590ae00a01cb1a2ed48def3915f)
- wolfCrypt: [RC4 may dereference empty key](https://github.com/wolfSSL/wolfssl/pull/2578)
- wolfCrypt: [SCRYPT leaves output buffer uninitialized](https://github.com/wolfSSL/wolfssl/pull/2578)
- wolfCrypt: wc_HKDF + BLAKE2B leaves output buffer uninitialized
- wolfCrypt: [PKCS12 PBKDF + SHA3 buffer overflow](https://github.com/wolfSSL/wolfssl/pull/2677)
- NSS: mp_toradix buffer overflow (write) TBA
- BLAKE3: [memcpy undefined behavior in C impl](https://github.com/BLAKE3-team/BLAKE3/pull/4)
- sjcl: [scrypt wrong result with certain parameters](https://github.com/bitwiseshiftleft/sjcl/issues/409)
- sjcl: [RIPEMD160 HMAC wrong result](https://github.com/bitwiseshiftleft/sjcl/issues/410)
- sjcl: [bignum subtraction incorrect result](https://github.com/bitwiseshiftleft/sjcl/issues/411)
- NSS: [SEEK ECB leaves output buffer uninitialized when encrypting more than 1 block](https://hg.mozilla.org/projects/nss/rev/d67517e92371ba798751720f7d21968ab2e25c52)
- libgcrypt: [gcry_mpi_invm indicates multiplicative inverse exists when it does not](https://lists.gnupg.org/pipermail/gcrypt-devel/2020-April/004947.html)
- wolfCrypt: [AES GCM allows IV of size 0](https://github.com/wolfSSL/wolfssl/pull/2910)
- wolfCrypt: [AES CCM allows invalid tag sizes](https://github.com/wolfSSL/wolfssl/pull/2930)
- LibreSSL: [AES GCM allows IV of size 0](https://github.com/openbsd/src/commit/539125b0baa78c5c019ab9e3bbeca4fa822d1bf7)
- OpenSSL: [CAST5 invalid output](https://github.com/openssl/openssl/issues/11459)
- Crypto++: [SPECK64 different output if input is passed in chunks](https://github.com/weidai11/cryptopp/issues/945)
- Crypto++: [Undersized SipHash key leads to buffer out-of-bounds read](https://github.com/weidai11/cryptopp/issues/947)
- libkcapi: [PBKDF2 with iteration count = 0 zeroes output buffer](https://github.com/smuellerDD/libkcapi/issues/93)
- wolfCrypt: [HKDF allows key sizes > 255 * digest size TBA](https://github.com/wolfSSL/wolfssl/pull/2956)
- Botan: [HKDF clamps output to 255 * requested key size](https://github.com/randombit/botan/issues/2347)
- SymCrypt: [Signed overshift and other undefined behavior](https://github.com/microsoft/SymCrypt/issues/8)
- NSS: [ChaCha20, ChaCha20/Poly1305 OOB read, OOB write, incorrect output with multi-part updating or small AEAD tag, CVE-2020-12403](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.55_release_notes)
- OpenSSL: [AES key wrap ciphers out-of-bounds write](https://github.com/openssl/openssl/issues/12014)
- LibreSSL: [AES key wrap ciphers use-after-free](https://github.com/openbsd/src/commit/f72711c6fb8692f12b01b3a3b7f54687729f6f9b)
- OpenSSL: [AES key wrap ciphers use-after-free](https://github.com/openssl/openssl/issues/12073)
- Crypto++: [AES GCM encryption with large tag size results in incorrect output, out-of-bounds reads](https://github.com/weidai11/cryptopp/issues/954)
- mbed TLS: [mbedtls_md_setup memory leak if allocation fails](https://github.com/ARMmbed/mbedtls/issues/3486)
- OpenSSL: [EVP_CIPHER_CTX re-initialisation bugs](https://github.com/openssl/openssl/pull/12523)
- OpenSSL: [KBKDF NULL ptr dereference, possibly wrong output](https://github.com/openssl/openssl/issues/12409)
