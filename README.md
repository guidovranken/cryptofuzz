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
- OpenSSL: [KBKDF NULL ptr dereference](https://github.com/openssl/openssl/issues/12409)
- Botan: [PointGFp_Multi_Point_Precompute gives wrong result when an infinity point occurs in the precomputation](https://github.com/randombit/botan/issues/2424) (credit to @andrewkozlik)
- Botan: [ECDSA hash truncation discrepancy](https://github.com/randombit/botan/issues/2415)
- mbed TLS: [mbedtls_cipher_auth_encrypt with AES key wrap OOB write](https://github.com/ARMmbed/mbedtls/issues/3665)
- bignumber.js: [squareRoot() produces incorrect result](https://github.com/MikeMcl/bignumber.js/issues/276)
- elliptic: [Curves p384 and p521 produce incorrect results](https://github.com/indutny/elliptic/issues/239)
- Nettle: [Blowfish signed integer overshift](https://git.lysator.liu.se/nettle/nettle/-/commit/4c8b0cdd97ffec3ae3f8d995afdfccbc261b3c79)
- Golang: [crypto/ecdsa: signature verification succeeds when it should fail](https://github.com/golang/go/issues/42340)
- SymCrypt: [Elliptic curve private-to-public incorrect result on Linux 32 bit](https://github.com/microsoft/SymCrypt/issues/9)
- libtomcrypt: [PKBDF1 hang if iterations is 0](https://github.com/libtom/libtomcrypt/issues/552)
- libtomcrypt: [TEA cipher incorrect result](https://github.com/libtom/libtomcrypt/issues/553)
- SymCrypt: [NULL pointer access in struct offset resolution](https://github.com/microsoft/SymCrypt/issues/10)
- BearSSL: Carry propagation bug in ECC code. Commit: b2ec2030e40acf5e9e4cd0f2669aacb27eadb540
- Trezor firmware: [ECDSA verification fails if hash is curve order](https://github.com/trezor/trezor-firmware/pull/1374)
- Botan: [ECDSA verification succeeds with invalid public key](https://github.com/randombit/botan/commit/92cd9ad72184bacacb7682c1b65ff040ab2347ee)
- Botan: [KDF + BLAKE incorrect result](https://github.com/randombit/botan/issues/2525)
- Crypto++: [ECDSA verification succeeds with invalid signature](https://github.com/weidai11/cryptopp/issues/981)
- micro-ecc: [ECDSA verification fails when it should succeed](https://github.com/kmackay/micro-ecc/issues/179#issuecomment-734515934)
- Parity libsecp256k1: [RFC6979 signature discrepancy if input is curve order](https://github.com/paritytech/libsecp256k1/issues/62)
- LibreSSL: [ECDSA verification succeeds with invalid public key](https://github.com/openbsd/src/commit/ea076652f78324977b6dc08890965b6823672c02)
- SymCrypt: [Uninitialized memory used as array index in ECDSA verification if hash is 0](https://github.com/microsoft/SymCrypt/commit/13fa454049fa265fa9e929a3a508907d259024a6)
- TBA: TBA
- NSS/ecckiila: [ECDSA verification fails for all-zero hash](https://gitlab.com/nisec/ecckiila/-/commit/ec77867e336827705e67bb9b10538a7980b850fa)
- mbed TLS: [mbedtls_mpi_sub_abs memory corruption](https://github.com/ARMmbed/mbedtls/issues/4042)
- relic: [Out-of-bounds read via bn_sqr_basic](https://github.com/relic-toolkit/relic/issues/172)
- relic: [Wrong square root computation](https://github.com/relic-toolkit/relic/issues/173)
- relic: [ECDSA verification discrepancies](https://github.com/relic-toolkit/relic/issues/175)
- relic: [bn_write_str buffer overflow](https://github.com/relic-toolkit/relic/issues/176)
- Nettle: [ECDSA verification fails for all-zero hash](https://github.com/gnutls/nettle/commit/b3d0bcf5a185842d2c717927eef03577fd61a912)
- relic: [Buffer overflow via bn_mxp_slide](https://github.com/relic-toolkit/relic/commit/bba5b5fa5489706ab4eaf5d7d0c2550e0a9722c0)
- relic: [bn_mxp_monty incorrect result](https://github.com/relic-toolkit/relic/commit/d411fabf2358553937fffb3242a57ee711746859)
- relic: Several other memory and correctness bugs
- libgcrypt: [ECDSA verification succeeds with invalid public key](https://lists.gnupg.org/pipermail/gcrypt-devel/2021-January/005091.html)
- libgcrypt: [Out-of-bounds read in SHA256](https://lists.gnupg.org/pipermail/gcrypt-devel/2021-February/005105.html)
- SymCrypt: [Invalid ECDSA signature and public key for private key that is curve order](https://github.com/microsoft/SymCrypt/issues/12)
- SymCrypt: [ECDSA signing branches on uninitialized memory](https://github.com/microsoft/SymCrypt/issues/13)
- blst: [Modular inverse incorrect result](https://github.com/supranational/blst/security/advisories/GHSA-x279-68rr-jp4p)
- blst: [Inverse modulo hangs on i386 if input is 0 or multiple of modulo](https://github.com/supranational/blst/commit/dd980e7f81397895705c49fcb4f52e485bb45e21)
- blst  [Using non-standard 'dst' parameter branches on uninitialized memory](https://github.com/supranational/blst/commit/2bfee87adcf45c9d544bbc9486a8b6060044d93c)
- Botan: [Incorrect comparison of negative values](https://github.com/randombit/botan/issues/2638)
- blst: [NULL pointer dereference if msg is empty and aug is non-empty](https://github.com/supranational/blst/commit/02d63dac1459d6f9bee5043159c9c0908c1229ac)
- Nettle: [Crash, potential incorrect verification in ECDSA verification](https://lists.lysator.liu.se/pipermail/nettle-bugs/2021/009457.html)
- relic: [Modular exponentiation returns 1 if exponent is 0 and modulo is 1](https://github.com/relic-toolkit/relic/issues/185)
- Chia bls-signatures: TBA
- relic: [BLAKE2S160, BLAKE2S256 functions leave output buffer uninitialized if input is empty](https://github.com/relic-toolkit/relic/commit/1885ae3b681c423c72b65ce1fe70910142cf941c)
- Botan: [BigInt right-shifting can cause std::vector to throw std::length_error](https://github.com/randombit/botan/issues/2672)
- mbed TLS: [ECDSA signing of 0 produces unverifiable signature](https://github.com/ARMmbed/mbedtls/issues/4261)
- mbed TLS: [PKCS12 KDF + MD2 incorrect result](https://github.com/ARMmbed/mbedtls/issues/4267)
- libgcrypt [CMAC + SERPENT/IDEA/RC2 buffer overflow/crash with oversized key](https://lists.gnupg.org/pipermail/gcrypt-devel/2021-March/005130.html)
- Parity libsecp256k1: [Verifies signatures whose R,S > curve order](https://github.com/paritytech/libsecp256k1/commit/b525d5d318d9672a40250c1725fa1bb3156688b7)
- Botan: [ECDSA pubkey recovery succeeds with invalid parameters](https://github.com/randombit/botan/issues/2698)
- mbed TLS: [CHACHA20-POLY1305 succeeds with invalid IV size](https://github.com/ARMmbed/mbedtls/issues/4301)
- SymCrypt: [ECDSA signing produces invalid signature](https://github.com/microsoft/SymCrypt/issues/15)
- BLAKE reference implementation: [Updating with empty buffer resets internal counter](https://github.com/trezor/trezor-firmware/commit/b2cc3bcb369b163e31b3f34608878be7f9410a64)
- Herumi mcl: [Incorrect results with dst larger than 255 bytes](https://github.com/herumi/mcl/commit/b01ef452a5a4acae584c0b27956cbf55b5275607)
- LibreSSL: [EC_POINT_point2oct / EC_POINT_oct2point asymmetry](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/lib/libcrypto/ec/ec2_oct.c?rev=1.13&content-type=text/x-cvsweb-markup)
- noble-secp256k1: Several ECDSA verification bugs: [1](https://github.com/paulmillr/noble-secp256k1/commit/13da0de79bf3b04f892f8d73bd4b5657a7329828) [2](https://github.com/paulmillr/noble-secp256k1/commit/9082b405a3d1958b5b6a699bb408215ae30eea5b) [3](https://github.com/paulmillr/noble-secp256k1/commit/c514f79ebdab1042dac214446f1ca32214a5edfd)
- blst: [NULL pointer dereference if point multiplier is zero-stripped](https://github.com/supranational/blst/commit/9a9d57d5a11b52b46d358ffbb995013cd1ac1faa)
- libecc: [Use of uninitialized memory in ECGDSA signing](https://github.com/ANSSI-FR/libecc/commit/57016705636b66f146bd437172dc1950fd71aec4)
- noble-ed25519: [Accepts overlong private keys](https://github.com/paulmillr/noble-ed25519/commit/c726f5202fd82062d645e1cd0ebbfdbd3e81a0fc)
- relic: [Elliptic curve point multiplication incorrect result if input X = 0](https://github.com/relic-toolkit/relic/issues/206)
- relic: [Incorrect point validation](https://github.com/relic-toolkit/relic/commit/7ed8e702db74d5d5a83b0bfaf9ee8e33a70e36ed)
- Chia/relic: Allows loading invalid point [1](https://github.com/Chia-Network/bls-signatures/issues/247) [2](https://github.com/Chia-Network/bls-signatures/issues/251)
- blst: [Branching on uninitialize memory](https://github.com/supranational/blst/commit/eb6151961c133a930420e844e1a84708fbb4f6a4)
- num-bigint: [Panic on multiplication](https://github.com/rust-num/num-bigint/security/advisories/GHSA-v935-pqmr-g8v9)
- Botan: [Produces invalid ECDSA signatures](https://github.com/randombit/botan/issues/2841)
- libgcrypt: [gcry_mpi_sub_ui result is positive when it should be negative](https://lists.gnupg.org/pipermail/gcrypt-devel/2021-November/005191.html)
- Decred uint256: [Incorrect decimal string formatting](https://github.com/decred/dcrd/pull/2844)
- Botan: [Undefined behavior upon instantiating DL_Group](https://github.com/randombit/botan/issues/2861)
- libtommath: [mp_is_square says 0 is not a square](https://github.com/libtom/libtommath/issues/521)
- OpenSSL: [HMAC use-after-free after copying ctx](https://github.com/openssl/openssl/issues/17261)
- Golang: [CVE-2022-23806: crypto/elliptic: IsOnCurve returns true for invalid field elements](https://github.com/golang/go/issues/50974)
- mbed TLS: [mbedtls_ecp_muladd hangs with oversized point coordinates](https://github.com/ARMmbed/mbedtls/issues/5376)
- BoringSSL: [EVP_AEAD_CTX_free NULL pointer dereference if pointer is NULL](https://bugs.chromium.org/p/boringssl/issues/detail?id=473)
- blst: [blst_fr_eucl_inverse incorrect result](https://github.com/supranational/blst/commit/fd453524b12cc438adc65636fc52375b0f47b17e)
- circl: [Inadequate scalar reduction in p384 leads to panic](https://github.com/cloudflare/circl/issues/312)
- Herumi mcl: [map-to-curve incorrect result if both inputs are equivalent](https://github.com/herumi/mcl/commit/0ddbe946423acd5cee2552b09373f4e1e9ba4023)
- OpenSSL: [BN_mod_exp2_mont NULL pointer dereference if modulus is 0](https://github.com/openssl/openssl/issues/17648)
- relic: [bn_mod_pmers hangs if modulus is 0](https://github.com/relic-toolkit/relic/issues/221)
- relic: [bn_mod_barrt out-of-bounds write and hang](https://github.com/relic-toolkit/relic/issues/222)
- relic: [bn_gcd_ext_stein returns different Bezout coefficients](https://github.com/relic-toolkit/relic/issues/223)
- Zig: [std.math.big.int panics (divFloor, gcd, bitAnd)](https://github.com/ziglang/zig/issues/10932)
- NSS: [mp_xgcd produces incorrect Bezout coefficients](https://bugzilla.mozilla.org/show_bug.cgi?id=1761708)
- Nettle: TBA
- libgcrypt: [Argon2 incorrect result and division by zero](https://lists.gnupg.org/pipermail/gcrypt-devel/2022-March/005290.html)
- Herumi mcl: [Incorrect result for G1 multiplication by Fp](https://github.com/herumi/mcl/issues/141)
- libgcrypt: [gcry_mpi_invm incorrect result](https://lists.gnupg.org/pipermail/gcrypt-devel/2022-April/005303.html)
- OpenSSL, LibreSSL: [Incorrect NIST curve math](https://cvsweb.openbsd.org/src/lib/libcrypto/bn/bn_nist.c?rev=1.20&content-type=text/x-cvsweb-markup)
- relic: [bn_lcm incorrect result with negative zero input](https://github.com/relic-toolkit/relic/issues/235)
- relic: [bn_gcd_lehme hangs with negative input](https://github.com/relic-toolkit/relic/issues/236)
- relic: [Modulo functions hang with negative inputs](https://github.com/relic-toolkit/relic/issues/237)
- blst: [blst_fp_is_square incorrect result on ARM](https://github.com/supranational/blst/commit/69d380745b64c8e72128263434762770a9162622)
- OpenSSL, BoringSSL: [BN_mod_exp_mont_consttime returns modulus when it should return 0](https://boringssl-review.googlesource.com/c/boringssl/+/52825)
- libgcrypt: [Allows invalid HKDF output sizes](https://lists.gnupg.org/pipermail/gcrypt-devel/2022-June/005328.html)
- libgmp mini-gmp: [mpz_powm incorrect result](https://gmplib.org/list-archives/gmp-bugs/2022-August/005183.html)
- mbed TLS: [mbedtls_mpi_mod_int produces incorrect results](https://github.com/Mbed-TLS/mbedtls/issues/6540)
- Zig: [HKDF rejects maximum key size](https://github.com/ziglang/zig/issues/14050)
- Zig: [HMAC + SHA3 incorrect output](https://github.com/ziglang/zig/issues/14128)
- Nim bigints: [Division causes assert failure](https://github.com/nim-lang/bigints/issues/123)
- D: [std.bigint powmod incorrect result on Ubuntu 20.04](https://bugs.launchpad.net/ubuntu/+source/ldc/+bug/2003613)
- Golang: [CVE-2023-24532: Specific unreduced P-256 scalars produce incorrect results](https://github.com/golang/go/issues/58647)
- OpenSSL, LibreSSL, BoringSSL: [DSA signing hangs with invalid parameters](https://github.com/openssl/openssl/issues/20268)
- Zig: [Streaming SHA3 incorrect output](https://github.com/ziglang/zig/issues/14851)
- Zig: [Argon2 outputs uninitialized memory with keysize > 64](https://github.com/ziglang/zig/issues/14912)
- Boost multiprecision: [Loading cpp_int by std::string branches on uninitialized memory](https://github.com/boostorg/multiprecision/issues/526)
- Zig: [secp256k1 scalar multiplication panics](https://github.com/ziglang/zig/issues/15267)
- kilic-bls12-381: [Fr FromBytes does not reduce value if value is modulus](https://github.com/kilic/bls12-381/issues/40)
- OpenSSL, LibreSSL, BoringSSL: [BN_mod_inverse incorrect result when parameters are aliased](https://github.com/openssl/openssl/issues/21110)
- libgcrypt: [Modular add/sub/mul incorrect result if result and modulus pointer are equal](https://lists.gnupg.org/pipermail/gcrypt-devel/2023-June/005507.html)
- libecc: [nn_modinv_2exp incorrect result if exponent is 0](https://github.com/libecc/libecc/commit/049eb1970374b48c5f93c5afc5f6f56503942cc8)
- libecc: [Modular addition incorrect result if result and modulus pointer are equal](https://github.com/libecc/libecc/commit/2479434f054a6020314a448ba932e659f57a3ae2)
- NEAR modexp precompile: [Panic if exponent is 0](https://github.com/aurora-is-near/aurora-engine/pull/771)
- arkworks-algebra: [multi_scalar_mul incorrect result if scalar exceeds curve order](https://github.com/arkworks-rs/algebra/issues/656)
- Golang: [crypto/ecdsa: P521 ecdsa.Verify panics with malformed message](https://github.com/golang/go/issues/60741)
- Golang: [crypto/elliptic: P256 ScalarBaseMult with order-34 yields point at infinity](https://github.com/golang/go/issues/60717)
- Zig: [Elliptic curve point addition incorrect result](https://github.com/ziglang/zig/issues/16015)
- Botan: [BigInt::random_integer hangs](https://github.com/randombit/botan/issues/3590)
- Constantine: [Incorrect reduction of BigInt](https://github.com/mratsim/constantine/pull/246)
- Constantine: [Modular exponentiation incorrect result with power-of-2 modulus](https://github.com/mratsim/constantine/pull/247)
- Constantine: [Slow repeated modular exponentiation](https://github.com/mratsim/constantine/pull/249)
- Constantine: [BLS12-381 HashToCurve G1 incorrect result](https://github.com/mratsim/constantine/pull/250)
- Constantine: [Modular exponentiation crash](https://github.com/mratsim/constantine/pull/251)
- libtommath: [mp_exptmod incorrect result](https://github.com/libtom/libtommath/issues/563)
- Botan: [Undefined behavior in AlignmentBuffer::fill_up_with_zeros](https://github.com/randombit/botan/issues/3734)
