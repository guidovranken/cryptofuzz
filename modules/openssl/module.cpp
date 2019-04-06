#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace module {

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
#if 1
static void* OPENSSL_custom_malloc(size_t n, const char* file, int line) {
    (void)file;
    (void)line;

    return util::malloc(n);
}

static void* OPENSSL_custom_realloc(void* ptr, size_t n, const char* file, int line) {
    (void)file;
    (void)line;

    return util::realloc(ptr, n);
}

static void OPENSSL_custom_free(void* ptr, const char* file, int line) {
    (void)file;
    (void)line;

    util::free(ptr);
}
#endif
#endif

OpenSSL::OpenSSL(void) :
    Module("OpenSSL") {
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
#if 1
    if ( CRYPTO_set_mem_functions(
                OPENSSL_custom_malloc,
                OPENSSL_custom_realloc,
                OPENSSL_custom_free) != 1 ) {
        abort();
    }
#endif
#endif

#if !defined(CRYPTOFUZZ_OPENSSL_102)
     OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
#else
     OpenSSL_add_all_algorithms();
#endif
}

const EVP_MD* OpenSSL::toEVPMD(const component::DigestType& digestType) const {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, const EVP_MD*> LUT = {
#if defined(CRYPTOFUZZ_BORINGSSL)
        { ID("Cryptofuzz/Digest/SHA1"), EVP_sha1() },
        { ID("Cryptofuzz/Digest/SHA224"), EVP_sha224() },
        { ID("Cryptofuzz/Digest/SHA256"), EVP_sha256() },
        { ID("Cryptofuzz/Digest/SHA384"), EVP_sha384() },
        { ID("Cryptofuzz/Digest/SHA512"), EVP_sha512() },
        { ID("Cryptofuzz/Digest/MD4"), EVP_md4() },
        { ID("Cryptofuzz/Digest/MD5"), EVP_md5() },
        { ID("Cryptofuzz/Digest/MD5_SHA1"), EVP_md5_sha1() },
#elif defined(CRYPTOFUZZ_LIBRESSL)
        { ID("Cryptofuzz/Digest/SHA1"), EVP_sha1() },
        { ID("Cryptofuzz/Digest/SHA224"), EVP_sha224() },
        { ID("Cryptofuzz/Digest/SHA256"), EVP_sha256() },
        { ID("Cryptofuzz/Digest/SHA384"), EVP_sha384() },
        { ID("Cryptofuzz/Digest/SHA512"), EVP_sha512() },
        { ID("Cryptofuzz/Digest/MD4"), EVP_md4() },
        { ID("Cryptofuzz/Digest/MD5"), EVP_md5() },
        { ID("Cryptofuzz/Digest/MD5_SHA1"), EVP_md5_sha1() },
        { ID("Cryptofuzz/Digest/RIPEMD160"), EVP_ripemd160() },
        { ID("Cryptofuzz/Digest/WHIRLPOOL"), EVP_whirlpool() },
        { ID("Cryptofuzz/Digest/SM3"), EVP_sm3() },
        { ID("Cryptofuzz/Digest/GOST-R-34.11-94"), EVP_gostr341194() },
        { ID("Cryptofuzz/Digest/GOST-28147-89"), EVP_gost2814789imit() },
        { ID("Cryptofuzz/Digest/STREEBOG-256"), EVP_streebog256() },
        { ID("Cryptofuzz/Digest/STREEBOG-512"), EVP_streebog512() },
#elif defined(CRYPTOFUZZ_OPENSSL_102)
        { ID("Cryptofuzz/Digest/SHA1"), EVP_sha1() },
        { ID("Cryptofuzz/Digest/SHA224"), EVP_sha224() },
        { ID("Cryptofuzz/Digest/SHA256"), EVP_sha256() },
        { ID("Cryptofuzz/Digest/SHA384"), EVP_sha384() },
        { ID("Cryptofuzz/Digest/SHA512"), EVP_sha512() },
        { ID("Cryptofuzz/Digest/MD2"), EVP_md2() },
        { ID("Cryptofuzz/Digest/MD4"), EVP_md4() },
        { ID("Cryptofuzz/Digest/MD5"), EVP_md5() },
        { ID("Cryptofuzz/Digest/MDC2"), EVP_mdc2() },
        { ID("Cryptofuzz/Digest/RIPEMD160"), EVP_ripemd160() },
        { ID("Cryptofuzz/Digest/WHIRLPOOL"), EVP_whirlpool() },
#else
        { ID("Cryptofuzz/Digest/SHA1"), EVP_sha1() },
        { ID("Cryptofuzz/Digest/SHA224"), EVP_sha224() },
        { ID("Cryptofuzz/Digest/SHA256"), EVP_sha256() },
        { ID("Cryptofuzz/Digest/SHA384"), EVP_sha384() },
        { ID("Cryptofuzz/Digest/SHA512"), EVP_sha512() },
        { ID("Cryptofuzz/Digest/MD2"), EVP_md2() },
        { ID("Cryptofuzz/Digest/MD4"), EVP_md4() },
        { ID("Cryptofuzz/Digest/MD5"), EVP_md5() },
        { ID("Cryptofuzz/Digest/MD5_SHA1"), EVP_md5_sha1() },
        { ID("Cryptofuzz/Digest/MDC2"), EVP_mdc2() },
        { ID("Cryptofuzz/Digest/RIPEMD160"), EVP_ripemd160() },
        { ID("Cryptofuzz/Digest/WHIRLPOOL"), EVP_whirlpool() },
        { ID("Cryptofuzz/Digest/SM3"), EVP_sm3() },
        { ID("Cryptofuzz/Digest/BLAKE2B512"), EVP_blake2b512() },
        { ID("Cryptofuzz/Digest/BLAKE2S256"), EVP_blake2s256() },
        { ID("Cryptofuzz/Digest/SHAKE128"), EVP_shake128() },
        { ID("Cryptofuzz/Digest/SHAKE256"), EVP_shake256() },
        { ID("Cryptofuzz/Digest/SHA3-224"), EVP_sha3_224() },
        { ID("Cryptofuzz/Digest/SHA3-256"), EVP_sha3_256() },
        { ID("Cryptofuzz/Digest/SHA3-384"), EVP_sha3_384() },
        { ID("Cryptofuzz/Digest/SHA3-512"), EVP_sha3_512() },
        { ID("Cryptofuzz/Digest/SHA512-224"), EVP_sha512_224() },
        { ID("Cryptofuzz/Digest/SHA512-256"), EVP_sha512_256() },
#endif
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        return nullptr;
    }

    return LUT.at(digestType.Get());
}

const EVP_CIPHER* OpenSSL::toEVPCIPHER(const component::SymmetricCipherType cipherType) const {
    using fuzzing::datasource::ID;

    switch ( cipherType.Get() ) {
#if defined(CRYPTOFUZZ_BORINGSSL)
        case ID("Cryptofuzz/Cipher/DES_CBC"):
            return EVP_des_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case ID("Cryptofuzz/Cipher/DES_ECB"):
            return EVP_des_ecb();
        case ID("Cryptofuzz/Cipher/DES_EDE"):
            return EVP_des_ede();
        case ID("Cryptofuzz/Cipher/DES_EDE3"):
            return EVP_des_ede3();
        case ID("Cryptofuzz/Cipher/RC2_CBC"):
            return EVP_rc2_cbc();
        case ID("Cryptofuzz/Cipher/RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_ECB"):
            return EVP_aes_128_ecb();
        case ID("Cryptofuzz/Cipher/AES_128_CBC"):
            return EVP_aes_128_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_OFB"):
            return EVP_aes_128_ofb();
        case ID("Cryptofuzz/Cipher/AES_128_CTR"):
            return EVP_aes_128_ctr();
        case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            return EVP_aes_128_gcm();
        case ID("Cryptofuzz/Cipher/AES_192_ECB"):
            return EVP_aes_192_ecb();
        case ID("Cryptofuzz/Cipher/AES_192_CBC"):
            return EVP_aes_192_cbc();
        case ID("Cryptofuzz/Cipher/AES_192_OFB"):
            return EVP_aes_192_ofb();
        case ID("Cryptofuzz/Cipher/AES_192_CTR"):
            return EVP_aes_192_ctr();
        case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            return EVP_aes_192_gcm();
        case ID("Cryptofuzz/Cipher/AES_256_ECB"):
            return EVP_aes_256_ecb();
        case ID("Cryptofuzz/Cipher/AES_256_CBC"):
            return EVP_aes_256_cbc();
        case ID("Cryptofuzz/Cipher/AES_256_OFB"):
            return EVP_aes_256_ofb();
        case ID("Cryptofuzz/Cipher/AES_256_CTR"):
            return EVP_aes_256_ctr();
        case ID("Cryptofuzz/Cipher/AES_256_GCM"):
            return EVP_aes_256_gcm();
        case ID("Cryptofuzz/Cipher/RC4"):
            return EVP_rc4();
#elif defined(CRYPTOFUZZ_LIBRESSL)
        case ID("Cryptofuzz/Cipher/DES_CFB"):
            return EVP_des_cfb();
        case ID("Cryptofuzz/Cipher/DES_CFB1"):
            return EVP_des_cfb1();
        case ID("Cryptofuzz/Cipher/DES_CFB8"):
            return EVP_des_cfb8();
        case ID("Cryptofuzz/Cipher/DES_EDE_CFB"):
            return EVP_des_ede_cfb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB"):
            return EVP_des_ede3_cfb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB1"):
            return EVP_des_ede3_cfb1();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB8"):
            return EVP_des_ede3_cfb8();
        case ID("Cryptofuzz/Cipher/DES_OFB"):
            return EVP_des_ofb();
        case ID("Cryptofuzz/Cipher/DES_EDE_OFB"):
            return EVP_des_ede_ofb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_OFB"):
            return EVP_des_ede3_ofb();
        case ID("Cryptofuzz/Cipher/DESX_CBC"):
            return EVP_desx_cbc();
        case ID("Cryptofuzz/Cipher/DES_CBC"):
            return EVP_des_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case ID("Cryptofuzz/Cipher/DES_ECB"):
            return EVP_des_ecb();
        case ID("Cryptofuzz/Cipher/DES_EDE"):
            return EVP_des_ede();
        case ID("Cryptofuzz/Cipher/DES_EDE3"):
            return EVP_des_ede3();
        case ID("Cryptofuzz/Cipher/RC4"):
            return EVP_rc4();
        case ID("Cryptofuzz/Cipher/RC4_40"):
            return EVP_rc4_40();
        case ID("Cryptofuzz/Cipher/RC4_HMAC_MD5"):
            return EVP_rc4_hmac_md5();
        case ID("Cryptofuzz/Cipher/IDEA_ECB"):
            return EVP_idea_ecb();
        case ID("Cryptofuzz/Cipher/IDEA_CFB"):
            return EVP_idea_cfb();
        case ID("Cryptofuzz/Cipher/IDEA_OFB"):
            return EVP_idea_ofb();
        case ID("Cryptofuzz/Cipher/IDEA_CBC"):
            return EVP_idea_cbc();
        case ID("Cryptofuzz/Cipher/SM4_ECB"):
            return EVP_sm4_ecb();
        case ID("Cryptofuzz/Cipher/SM4_CBC"):
            return EVP_sm4_cbc();
        case ID("Cryptofuzz/Cipher/SM4_CFB"):
            return EVP_sm4_cfb();
        case ID("Cryptofuzz/Cipher/SM4_OFB"):
            return EVP_sm4_ofb();
        case ID("Cryptofuzz/Cipher/SM4_CTR"):
            return EVP_sm4_ctr();
        case ID("Cryptofuzz/Cipher/RC2_ECB"):
            return EVP_rc2_ecb();
        case ID("Cryptofuzz/Cipher/RC2_CFB"):
            return EVP_rc2_cfb();
        case ID("Cryptofuzz/Cipher/RC2_OFB"):
            return EVP_rc2_ofb();
        case ID("Cryptofuzz/Cipher/RC2_CBC"):
            return EVP_rc2_cbc();
        case ID("Cryptofuzz/Cipher/RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case ID("Cryptofuzz/Cipher/RC2_64_CBC"):
            return EVP_rc2_64_cbc();
        case ID("Cryptofuzz/Cipher/BF_ECB"):
            return EVP_bf_ecb();
        case ID("Cryptofuzz/Cipher/BF_CFB"):
            return EVP_bf_cfb();
        case ID("Cryptofuzz/Cipher/BF_OFB"):
            return EVP_bf_ofb();
        case ID("Cryptofuzz/Cipher/BF_CBC"):
            return EVP_bf_cbc();
        case ID("Cryptofuzz/Cipher/CAST5_ECB"):
            return EVP_cast5_ecb();
        case ID("Cryptofuzz/Cipher/CAST5_CFB"):
            return EVP_cast5_cfb();
        case ID("Cryptofuzz/Cipher/CAST5_OFB"):
            return EVP_cast5_ofb();
        case ID("Cryptofuzz/Cipher/CAST5_CBC"):
            return EVP_cast5_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_ECB"):
            return EVP_aes_128_ecb();
        case ID("Cryptofuzz/Cipher/AES_128_CBC"):
            return EVP_aes_128_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_CFB"):
            return EVP_aes_128_cfb();
        case ID("Cryptofuzz/Cipher/AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case ID("Cryptofuzz/Cipher/AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case ID("Cryptofuzz/Cipher/AES_128_OFB"):
            return EVP_aes_128_ofb();
        case ID("Cryptofuzz/Cipher/AES_128_CTR"):
            return EVP_aes_128_ctr();
        case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            return EVP_aes_128_gcm();
        case ID("Cryptofuzz/Cipher/AES_128_XTS"):
            return EVP_aes_128_xts();
        case ID("Cryptofuzz/Cipher/AES_128_CCM"):
            return EVP_aes_128_ccm();
        case ID("Cryptofuzz/Cipher/AES_128_WRAP"):
            return EVP_aes_128_wrap();
        case ID("Cryptofuzz/Cipher/AES_192_ECB"):
            return EVP_aes_192_ecb();
        case ID("Cryptofuzz/Cipher/AES_192_CBC"):
            return EVP_aes_192_cbc();
        case ID("Cryptofuzz/Cipher/AES_192_CFB"):
            return EVP_aes_192_cfb();
        case ID("Cryptofuzz/Cipher/AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case ID("Cryptofuzz/Cipher/AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case ID("Cryptofuzz/Cipher/AES_192_OFB"):
            return EVP_aes_192_ofb();
        case ID("Cryptofuzz/Cipher/AES_192_CTR"):
            return EVP_aes_192_ctr();
        case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            return EVP_aes_192_gcm();
        case ID("Cryptofuzz/Cipher/AES_192_CCM"):
            return EVP_aes_192_ccm();
        case ID("Cryptofuzz/Cipher/AES_192_WRAP"):
            return EVP_aes_192_wrap();
        case ID("Cryptofuzz/Cipher/AES_256_ECB"):
            return EVP_aes_256_ecb();
        case ID("Cryptofuzz/Cipher/AES_256_CBC"):
            return EVP_aes_256_cbc();
        case ID("Cryptofuzz/Cipher/AES_256_CFB"):
            return EVP_aes_256_cfb();
        case ID("Cryptofuzz/Cipher/AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case ID("Cryptofuzz/Cipher/AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case ID("Cryptofuzz/Cipher/AES_256_OFB"):
            return EVP_aes_256_ofb();
        case ID("Cryptofuzz/Cipher/AES_256_CTR"):
            return EVP_aes_256_ctr();
        case ID("Cryptofuzz/Cipher/AES_256_GCM"):
            return EVP_aes_256_gcm();
        case ID("Cryptofuzz/Cipher/AES_256_XTS"):
            return EVP_aes_256_xts();
        case ID("Cryptofuzz/Cipher/AES_256_CCM"):
            return EVP_aes_256_ccm();
        case ID("Cryptofuzz/Cipher/AES_256_WRAP"):
            return EVP_aes_256_wrap();
        case ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA1"):
            return EVP_aes_128_cbc_hmac_sha1();
        case ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA1"):
            return EVP_aes_256_cbc_hmac_sha1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_ECB"):
            return EVP_camellia_128_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"):
            return EVP_camellia_128_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB"):
            return EVP_camellia_128_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB1"):
            return EVP_camellia_128_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB8"):
            return EVP_camellia_128_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_OFB"):
            return EVP_camellia_128_ofb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_ECB"):
            return EVP_camellia_192_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"):
            return EVP_camellia_192_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB"):
            return EVP_camellia_192_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB1"):
            return EVP_camellia_192_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB8"):
            return EVP_camellia_192_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_OFB"):
            return EVP_camellia_192_ofb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_ECB"):
            return EVP_camellia_256_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"):
            return EVP_camellia_256_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB"):
            return EVP_camellia_256_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB1"):
            return EVP_camellia_256_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB8"):
            return EVP_camellia_256_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_OFB"):
            return EVP_camellia_256_ofb();
        case ID("Cryptofuzz/Cipher/CHACHA20"):
            return EVP_chacha20();
#elif defined(CRYPTOFUZZ_OPENSSL_102)
        case ID("Cryptofuzz/Cipher/DES_CFB"):
            return EVP_des_cfb();
        case ID("Cryptofuzz/Cipher/DES_CFB1"):
            return EVP_des_cfb1();
        case ID("Cryptofuzz/Cipher/DES_CFB8"):
            return EVP_des_cfb8();
        case ID("Cryptofuzz/Cipher/DES_EDE_CFB"):
            return EVP_des_ede_cfb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB"):
            return EVP_des_ede3_cfb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB1"):
            return EVP_des_ede3_cfb1();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB8"):
            return EVP_des_ede3_cfb8();
        case ID("Cryptofuzz/Cipher/DES_OFB"):
            return EVP_des_ofb();
        case ID("Cryptofuzz/Cipher/DES_EDE_OFB"):
            return EVP_des_ede_ofb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_OFB"):
            return EVP_des_ede3_ofb();
        case ID("Cryptofuzz/Cipher/DESX_CBC"):
            return EVP_desx_cbc();
        case ID("Cryptofuzz/Cipher/DES_CBC"):
            return EVP_des_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case ID("Cryptofuzz/Cipher/DES_ECB"):
            return EVP_des_ecb();
        case ID("Cryptofuzz/Cipher/DES_EDE"):
            return EVP_des_ede();
        case ID("Cryptofuzz/Cipher/DES_EDE3"):
            return EVP_des_ede3();
        case ID("Cryptofuzz/Cipher/DES_EDE3_WRAP"):
            return EVP_des_ede3_wrap();
        case ID("Cryptofuzz/Cipher/RC4"):
            return EVP_rc4();
        case ID("Cryptofuzz/Cipher/RC4_40"):
            return EVP_rc4_40();
        case ID("Cryptofuzz/Cipher/RC4_HMAC_MD5"):
            return EVP_rc4_hmac_md5();
        case ID("Cryptofuzz/Cipher/IDEA_ECB"):
            return EVP_idea_ecb();
        case ID("Cryptofuzz/Cipher/IDEA_CFB"):
            return EVP_idea_cfb();
        case ID("Cryptofuzz/Cipher/IDEA_OFB"):
            return EVP_idea_ofb();
        case ID("Cryptofuzz/Cipher/IDEA_CBC"):
            return EVP_idea_cbc();
        case ID("Cryptofuzz/Cipher/SEED_ECB"):
            return EVP_seed_ecb();
        case ID("Cryptofuzz/Cipher/SEED_CFB"):
            return EVP_seed_cfb();
        case ID("Cryptofuzz/Cipher/SEED_OFB"):
            return EVP_seed_ofb();
        case ID("Cryptofuzz/Cipher/SEED_CBC"):
            return EVP_seed_cbc();
        case ID("Cryptofuzz/Cipher/RC2_ECB"):
            return EVP_rc2_ecb();
        case ID("Cryptofuzz/Cipher/RC2_CFB"):
            return EVP_rc2_cfb();
        case ID("Cryptofuzz/Cipher/RC2_OFB"):
            return EVP_rc2_ofb();
        case ID("Cryptofuzz/Cipher/RC2_CBC"):
            return EVP_rc2_cbc();
        case ID("Cryptofuzz/Cipher/RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case ID("Cryptofuzz/Cipher/RC2_64_CBC"):
            return EVP_rc2_64_cbc();
        case ID("Cryptofuzz/Cipher/BF_ECB"):
            return EVP_bf_ecb();
        case ID("Cryptofuzz/Cipher/BF_CFB"):
            return EVP_bf_cfb();
        case ID("Cryptofuzz/Cipher/BF_OFB"):
            return EVP_bf_ofb();
        case ID("Cryptofuzz/Cipher/BF_CBC"):
            return EVP_bf_cbc();
        case ID("Cryptofuzz/Cipher/CAST5_ECB"):
            return EVP_cast5_ecb();
        case ID("Cryptofuzz/Cipher/CAST5_CFB"):
            return EVP_cast5_cfb();
        case ID("Cryptofuzz/Cipher/CAST5_OFB"):
            return EVP_cast5_ofb();
        case ID("Cryptofuzz/Cipher/CAST5_CBC"):
            return EVP_cast5_cbc();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_ECB"):
            return EVP_rc5_32_12_16_ecb();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_CFB"):
            return EVP_rc5_32_12_16_cfb();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_OFB"):
            return EVP_rc5_32_12_16_ofb();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_CBC"):
            return EVP_rc5_32_12_16_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_ECB"):
            return EVP_aes_128_ecb();
        case ID("Cryptofuzz/Cipher/AES_128_CBC"):
            return EVP_aes_128_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_CFB"):
            return EVP_aes_128_cfb();
        case ID("Cryptofuzz/Cipher/AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case ID("Cryptofuzz/Cipher/AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case ID("Cryptofuzz/Cipher/AES_128_OFB"):
            return EVP_aes_128_ofb();
        case ID("Cryptofuzz/Cipher/AES_128_CTR"):
            return EVP_aes_128_ctr();
        case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            return EVP_aes_128_gcm();
        case ID("Cryptofuzz/Cipher/AES_128_XTS"):
            return EVP_aes_128_xts();
        case ID("Cryptofuzz/Cipher/AES_128_CCM"):
            return EVP_aes_128_ccm();
        case ID("Cryptofuzz/Cipher/AES_128_WRAP"):
            return EVP_aes_128_wrap();
        case ID("Cryptofuzz/Cipher/AES_192_ECB"):
            return EVP_aes_192_ecb();
        case ID("Cryptofuzz/Cipher/AES_192_CBC"):
            return EVP_aes_192_cbc();
        case ID("Cryptofuzz/Cipher/AES_192_CFB"):
            return EVP_aes_192_cfb();
        case ID("Cryptofuzz/Cipher/AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case ID("Cryptofuzz/Cipher/AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case ID("Cryptofuzz/Cipher/AES_192_OFB"):
            return EVP_aes_192_ofb();
        case ID("Cryptofuzz/Cipher/AES_192_CTR"):
            return EVP_aes_192_ctr();
        case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            return EVP_aes_192_gcm();
        case ID("Cryptofuzz/Cipher/AES_192_CCM"):
            return EVP_aes_192_ccm();
        case ID("Cryptofuzz/Cipher/AES_192_WRAP"):
            return EVP_aes_192_wrap();
        case ID("Cryptofuzz/Cipher/AES_256_ECB"):
            return EVP_aes_256_ecb();
        case ID("Cryptofuzz/Cipher/AES_256_CBC"):
            return EVP_aes_256_cbc();
        case ID("Cryptofuzz/Cipher/AES_256_CFB"):
            return EVP_aes_256_cfb();
        case ID("Cryptofuzz/Cipher/AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case ID("Cryptofuzz/Cipher/AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case ID("Cryptofuzz/Cipher/AES_256_OFB"):
            return EVP_aes_256_ofb();
        case ID("Cryptofuzz/Cipher/AES_256_CTR"):
            return EVP_aes_256_ctr();
        case ID("Cryptofuzz/Cipher/AES_256_GCM"):
            return EVP_aes_256_gcm();
        case ID("Cryptofuzz/Cipher/AES_256_XTS"):
            return EVP_aes_256_xts();
        case ID("Cryptofuzz/Cipher/AES_256_CCM"):
            return EVP_aes_256_ccm();
        case ID("Cryptofuzz/Cipher/AES_256_WRAP"):
            return EVP_aes_256_wrap();
        case ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA1"):
            return EVP_aes_128_cbc_hmac_sha1();
        case ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA1"):
            return EVP_aes_256_cbc_hmac_sha1();
        case ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA256"):
            return EVP_aes_128_cbc_hmac_sha256();
        case ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA256"):
            return EVP_aes_256_cbc_hmac_sha256();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_ECB"):
            return EVP_camellia_128_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"):
            return EVP_camellia_128_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB"):
            return EVP_camellia_128_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB1"):
            return EVP_camellia_128_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB8"):
            return EVP_camellia_128_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_OFB"):
            return EVP_camellia_128_ofb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_ECB"):
            return EVP_camellia_192_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"):
            return EVP_camellia_192_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB"):
            return EVP_camellia_192_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB1"):
            return EVP_camellia_192_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB8"):
            return EVP_camellia_192_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_OFB"):
            return EVP_camellia_192_ofb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_ECB"):
            return EVP_camellia_256_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"):
            return EVP_camellia_256_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB"):
            return EVP_camellia_256_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB1"):
            return EVP_camellia_256_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB8"):
            return EVP_camellia_256_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_OFB"):
            return EVP_camellia_256_ofb();
#else
        case ID("Cryptofuzz/Cipher/DES_CFB"):
            return EVP_des_cfb();
        case ID("Cryptofuzz/Cipher/DES_CFB1"):
            return EVP_des_cfb1();
        case ID("Cryptofuzz/Cipher/DES_CFB8"):
            return EVP_des_cfb8();
        case ID("Cryptofuzz/Cipher/DES_EDE_CFB"):
            return EVP_des_ede_cfb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB"):
            return EVP_des_ede3_cfb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB1"):
            return EVP_des_ede3_cfb1();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CFB8"):
            return EVP_des_ede3_cfb8();
        case ID("Cryptofuzz/Cipher/DES_OFB"):
            return EVP_des_ofb();
        case ID("Cryptofuzz/Cipher/DES_EDE_OFB"):
            return EVP_des_ede_ofb();
        case ID("Cryptofuzz/Cipher/DES_EDE3_OFB"):
            return EVP_des_ede3_ofb();
        case ID("Cryptofuzz/Cipher/DESX_CBC"):
            return EVP_desx_cbc();
        case ID("Cryptofuzz/Cipher/DES_CBC"):
            return EVP_des_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case ID("Cryptofuzz/Cipher/DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case ID("Cryptofuzz/Cipher/DES_ECB"):
            return EVP_des_ecb();
        case ID("Cryptofuzz/Cipher/DES_EDE"):
            return EVP_des_ede();
        case ID("Cryptofuzz/Cipher/DES_EDE3"):
            return EVP_des_ede3();
        case ID("Cryptofuzz/Cipher/DES_EDE3_WRAP"):
            return EVP_des_ede3_wrap();
        case ID("Cryptofuzz/Cipher/RC4"):
            return EVP_rc4();
        case ID("Cryptofuzz/Cipher/RC4_40"):
            return EVP_rc4_40();
        case ID("Cryptofuzz/Cipher/RC4_HMAC_MD5"):
            return EVP_rc4_hmac_md5();
        case ID("Cryptofuzz/Cipher/IDEA_ECB"):
            return EVP_idea_ecb();
        case ID("Cryptofuzz/Cipher/IDEA_CFB"):
            return EVP_idea_cfb();
        case ID("Cryptofuzz/Cipher/IDEA_OFB"):
            return EVP_idea_ofb();
        case ID("Cryptofuzz/Cipher/IDEA_CBC"):
            return EVP_idea_cbc();
        case ID("Cryptofuzz/Cipher/SEED_ECB"):
            return EVP_seed_ecb();
        case ID("Cryptofuzz/Cipher/SEED_CFB"):
            return EVP_seed_cfb();
        case ID("Cryptofuzz/Cipher/SEED_OFB"):
            return EVP_seed_ofb();
        case ID("Cryptofuzz/Cipher/SEED_CBC"):
            return EVP_seed_cbc();
        case ID("Cryptofuzz/Cipher/SM4_ECB"):
            return EVP_sm4_ecb();
        case ID("Cryptofuzz/Cipher/SM4_CBC"):
            return EVP_sm4_cbc();
        case ID("Cryptofuzz/Cipher/SM4_CFB"):
            return EVP_sm4_cfb();
        case ID("Cryptofuzz/Cipher/SM4_OFB"):
            return EVP_sm4_ofb();
        case ID("Cryptofuzz/Cipher/SM4_CTR"):
            return EVP_sm4_ctr();
        case ID("Cryptofuzz/Cipher/RC2_ECB"):
            return EVP_rc2_ecb();
        case ID("Cryptofuzz/Cipher/RC2_CFB"):
            return EVP_rc2_cfb();
        case ID("Cryptofuzz/Cipher/RC2_OFB"):
            return EVP_rc2_ofb();
        case ID("Cryptofuzz/Cipher/RC2_CBC"):
            return EVP_rc2_cbc();
        case ID("Cryptofuzz/Cipher/RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case ID("Cryptofuzz/Cipher/RC2_64_CBC"):
            return EVP_rc2_64_cbc();
        case ID("Cryptofuzz/Cipher/BF_ECB"):
            return EVP_bf_ecb();
        case ID("Cryptofuzz/Cipher/BF_CFB"):
            return EVP_bf_cfb();
        case ID("Cryptofuzz/Cipher/BF_OFB"):
            return EVP_bf_ofb();
        case ID("Cryptofuzz/Cipher/BF_CBC"):
            return EVP_bf_cbc();
        case ID("Cryptofuzz/Cipher/CAST5_ECB"):
            return EVP_cast5_ecb();
        case ID("Cryptofuzz/Cipher/CAST5_CFB"):
            return EVP_cast5_cfb();
        case ID("Cryptofuzz/Cipher/CAST5_OFB"):
            return EVP_cast5_ofb();
        case ID("Cryptofuzz/Cipher/CAST5_CBC"):
            return EVP_cast5_cbc();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_ECB"):
            return EVP_rc5_32_12_16_ecb();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_CFB"):
            return EVP_rc5_32_12_16_cfb();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_OFB"):
            return EVP_rc5_32_12_16_ofb();
        case ID("Cryptofuzz/Cipher/RC5_32_12_16_CBC"):
            return EVP_rc5_32_12_16_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_ECB"):
            return EVP_aes_128_ecb();
        case ID("Cryptofuzz/Cipher/AES_128_CBC"):
            return EVP_aes_128_cbc();
        case ID("Cryptofuzz/Cipher/AES_128_CFB"):
            return EVP_aes_128_cfb();
        case ID("Cryptofuzz/Cipher/AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case ID("Cryptofuzz/Cipher/AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case ID("Cryptofuzz/Cipher/AES_128_OFB"):
            return EVP_aes_128_ofb();
        case ID("Cryptofuzz/Cipher/AES_128_CTR"):
            return EVP_aes_128_ctr();
        case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            return EVP_aes_128_gcm();
        case ID("Cryptofuzz/Cipher/AES_128_OCB"):
            return EVP_aes_128_ocb();
        case ID("Cryptofuzz/Cipher/AES_128_XTS"):
            return EVP_aes_128_xts();
        case ID("Cryptofuzz/Cipher/AES_128_CCM"):
            return EVP_aes_128_ccm();
        case ID("Cryptofuzz/Cipher/AES_128_WRAP"):
            return EVP_aes_128_wrap();
        case ID("Cryptofuzz/Cipher/AES_128_WRAP_PAD"):
            return EVP_aes_128_wrap_pad();
        case ID("Cryptofuzz/Cipher/AES_192_ECB"):
            return EVP_aes_192_ecb();
        case ID("Cryptofuzz/Cipher/AES_192_CBC"):
            return EVP_aes_192_cbc();
        case ID("Cryptofuzz/Cipher/AES_192_CFB"):
            return EVP_aes_192_cfb();
        case ID("Cryptofuzz/Cipher/AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case ID("Cryptofuzz/Cipher/AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case ID("Cryptofuzz/Cipher/AES_192_OFB"):
            return EVP_aes_192_ofb();
        case ID("Cryptofuzz/Cipher/AES_192_CTR"):
            return EVP_aes_192_ctr();
        case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            return EVP_aes_192_gcm();
        case ID("Cryptofuzz/Cipher/AES_192_CCM"):
            return EVP_aes_192_ccm();
        case ID("Cryptofuzz/Cipher/AES_192_WRAP"):
            return EVP_aes_192_wrap();
        case ID("Cryptofuzz/Cipher/AES_192_WRAP_PAD"):
            return EVP_aes_192_wrap_pad();
        case ID("Cryptofuzz/Cipher/AES_256_ECB"):
            return EVP_aes_256_ecb();
        case ID("Cryptofuzz/Cipher/AES_256_CBC"):
            return EVP_aes_256_cbc();
        case ID("Cryptofuzz/Cipher/AES_256_CFB"):
            return EVP_aes_256_cfb();
        case ID("Cryptofuzz/Cipher/AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case ID("Cryptofuzz/Cipher/AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case ID("Cryptofuzz/Cipher/AES_256_OFB"):
            return EVP_aes_256_ofb();
        case ID("Cryptofuzz/Cipher/AES_256_CTR"):
            return EVP_aes_256_ctr();
        case ID("Cryptofuzz/Cipher/AES_256_GCM"):
            return EVP_aes_256_gcm();
        case ID("Cryptofuzz/Cipher/AES_256_OCB"):
            return EVP_aes_256_ocb();
        case ID("Cryptofuzz/Cipher/AES_256_XTS"):
            return EVP_aes_256_xts();
        case ID("Cryptofuzz/Cipher/AES_256_CCM"):
            return EVP_aes_256_ccm();
        case ID("Cryptofuzz/Cipher/AES_256_WRAP"):
            return EVP_aes_256_wrap();
        case ID("Cryptofuzz/Cipher/AES_256_WRAP_PAD"):
            return EVP_aes_256_wrap_pad();
        case ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA1"):
            return EVP_aes_128_cbc_hmac_sha1();
        case ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA1"):
            return EVP_aes_256_cbc_hmac_sha1();
        case ID("Cryptofuzz/Cipher/AES_128_CBC_HMAC_SHA256"):
            return EVP_aes_128_cbc_hmac_sha256();
        case ID("Cryptofuzz/Cipher/AES_256_CBC_HMAC_SHA256"):
            return EVP_aes_256_cbc_hmac_sha256();
        case ID("Cryptofuzz/Cipher/ARIA_128_ECB"):
            return EVP_aria_128_ecb();
        case ID("Cryptofuzz/Cipher/ARIA_128_CBC"):
            return EVP_aria_128_cbc();
        case ID("Cryptofuzz/Cipher/ARIA_128_CFB"):
            return EVP_aria_128_cfb();
        case ID("Cryptofuzz/Cipher/ARIA_128_CFB1"):
            return EVP_aria_128_cfb1();
        case ID("Cryptofuzz/Cipher/ARIA_128_CFB8"):
            return EVP_aria_128_cfb8();
        case ID("Cryptofuzz/Cipher/ARIA_128_CTR"):
            return EVP_aria_128_ctr();
        case ID("Cryptofuzz/Cipher/ARIA_128_OFB"):
            return EVP_aria_128_ofb();
        case ID("Cryptofuzz/Cipher/ARIA_128_GCM"):
            return EVP_aria_128_gcm();
        case ID("Cryptofuzz/Cipher/ARIA_128_CCM"):
            return EVP_aria_128_ccm();
        case ID("Cryptofuzz/Cipher/ARIA_192_ECB"):
            return EVP_aria_192_ecb();
        case ID("Cryptofuzz/Cipher/ARIA_192_CBC"):
            return EVP_aria_192_cbc();
        case ID("Cryptofuzz/Cipher/ARIA_192_CFB"):
            return EVP_aria_192_cfb();
        case ID("Cryptofuzz/Cipher/ARIA_192_CFB1"):
            return EVP_aria_192_cfb1();
        case ID("Cryptofuzz/Cipher/ARIA_192_CFB8"):
            return EVP_aria_192_cfb8();
        case ID("Cryptofuzz/Cipher/ARIA_192_CTR"):
            return EVP_aria_192_ctr();
        case ID("Cryptofuzz/Cipher/ARIA_192_OFB"):
            return EVP_aria_192_ofb();
        case ID("Cryptofuzz/Cipher/ARIA_192_GCM"):
            return EVP_aria_192_gcm();
        case ID("Cryptofuzz/Cipher/ARIA_192_CCM"):
            return EVP_aria_192_ccm();
        case ID("Cryptofuzz/Cipher/ARIA_256_ECB"):
            return EVP_aria_256_ecb();
        case ID("Cryptofuzz/Cipher/ARIA_256_CBC"):
            return EVP_aria_256_cbc();
        case ID("Cryptofuzz/Cipher/ARIA_256_CFB"):
            return EVP_aria_256_cfb();
        case ID("Cryptofuzz/Cipher/ARIA_256_CFB1"):
            return EVP_aria_256_cfb1();
        case ID("Cryptofuzz/Cipher/ARIA_256_CFB8"):
            return EVP_aria_256_cfb8();
        case ID("Cryptofuzz/Cipher/ARIA_256_CTR"):
            return EVP_aria_256_ctr();
        case ID("Cryptofuzz/Cipher/ARIA_256_OFB"):
            return EVP_aria_256_ofb();
        case ID("Cryptofuzz/Cipher/ARIA_256_GCM"):
            return EVP_aria_256_gcm();
        case ID("Cryptofuzz/Cipher/ARIA_256_CCM"):
            return EVP_aria_256_ccm();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_ECB"):
            return EVP_camellia_128_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"):
            return EVP_camellia_128_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB"):
            return EVP_camellia_128_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB1"):
            return EVP_camellia_128_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CFB8"):
            return EVP_camellia_128_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_OFB"):
            return EVP_camellia_128_ofb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_ECB"):
            return EVP_camellia_192_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"):
            return EVP_camellia_192_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB"):
            return EVP_camellia_192_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB1"):
            return EVP_camellia_192_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CFB8"):
            return EVP_camellia_192_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_OFB"):
            return EVP_camellia_192_ofb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_ECB"):
            return EVP_camellia_256_ecb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"):
            return EVP_camellia_256_cbc();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB"):
            return EVP_camellia_256_cfb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB1"):
            return EVP_camellia_256_cfb1();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CFB8"):
            return EVP_camellia_256_cfb8();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_OFB"):
            return EVP_camellia_256_ofb();
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CTR"):
            return EVP_camellia_128_ctr();
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CTR"):
            return EVP_camellia_192_ctr();
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CTR"):
            return EVP_camellia_256_ctr();
        case ID("Cryptofuzz/Cipher/CHACHA20"):
            return EVP_chacha20();
        case ID("Cryptofuzz/Cipher/CHACHA20_POLY1305"):
            return EVP_chacha20_poly1305();
#endif
        default:
            return nullptr;
    }
}

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
const EVP_AEAD* OpenSSL::toEVPAEAD(const component::SymmetricCipherType cipherType) const {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, const EVP_AEAD*> LUT = {
        { ID("Cryptofuzz/Cipher/CHACHA20_POLY1305"), EVP_aead_chacha20_poly1305() },
        { ID("Cryptofuzz/Cipher/XCHACHA20_POLY1305"), EVP_aead_xchacha20_poly1305() },
    };

    if ( LUT.find(cipherType.Get()) == LUT.end() ) {
        return nullptr;
    }

    return LUT.at(cipherType.Get());
}
#endif

std::optional<component::Ciphertext> OpenSSL::OpDigest(operation::Digest& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(ctx = EVP_MD_CTX_create(), nullptr);
        CF_CHECK_EQ(EVP_DigestInit_ex(ctx, md, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestUpdate(ctx, part.first, part.second), 1);
    }

    /* Finalize */
    {
        unsigned int len = -1;
        unsigned char md[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(EVP_DigestFinal_ex(ctx, md, &len), 1);

        ret = component::Digest(md, len);
    }

end:
    EVP_MD_CTX_destroy(ctx);

    return ret;
}

#if !defined(CRYPTOFUZZ_BORINGSSL)
std::optional<component::MAC> OpenSSL::OpHMAC_EVP(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;
    EVP_PKEY *pkey = nullptr;

    /* Initialize */
    {
        using fuzzing::datasource::ID;
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(ctx = EVP_MD_CTX_create(), nullptr);
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), nullptr);
        CF_CHECK_EQ(EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestSignUpdate(ctx, part.first, part.second), 1);
    }

    /* Finalize */
    {
        size_t len = -1;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(EVP_DigestSignFinal(ctx, out, &len), 1);

        ret = component::MAC(out, len);
    }

end:
    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(pkey);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_OPENSSL_102)
std::optional<component::MAC> OpenSSL::OpHMAC_HMAC(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    HMAC_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        using fuzzing::datasource::ID;
        parts = util::ToParts(ds, op.cleartext);
        CF_CHECK_NE(ctx = HMAC_CTX_new(), nullptr);
        /* TODO remove ? */
        HMAC_CTX_reset(ctx);
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_EQ(HMAC_Init_ex(ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize(), md, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(HMAC_Update(ctx, part.first, part.second), 1);
    }

    /* Finalize */
    {
        unsigned int len = -1;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(HMAC_Final(ctx, out, &len), 1);

        ret = component::MAC(out, len);
    }

end:
    HMAC_CTX_free(ctx);

    return ret;
}
#endif

std::optional<component::MAC> OpenSSL::OpHMAC(operation::HMAC& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( useEVP == true ) {
#if !defined(CRYPTOFUZZ_BORINGSSL)
        return OpHMAC_EVP(op, ds);
#else
        return OpHMAC_HMAC(op, ds);
#endif
    } else {
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        return OpHMAC_HMAC(op, ds);
#else
        return OpHMAC_EVP(op, ds);
#endif
    }
}

bool OpenSSL::checkSetIVLength(const uint64_t cipherType, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputIvLength) const {
    using fuzzing::datasource::ID;
    (void)ctx;

    bool ret = false;

    const size_t ivLength = EVP_CIPHER_iv_length(cipher);
    if ( ivLength != inputIvLength ) {
        switch ( cipherType ) {
#if defined(CRYPTOFUZZ_LIBRESSL) || defined(CRYPTOFUZZ_OPENSSL_102)
            case ID("Cryptofuzz/Cipher/AES_128_CCM"):
            case ID("Cryptofuzz/Cipher/AES_192_CCM"):
            case ID("Cryptofuzz/Cipher/AES_256_CCM"):
                CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, inputIvLength, nullptr), 1);
                break;
            case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            case ID("Cryptofuzz/Cipher/AES_256_GCM"):
                CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, inputIvLength, nullptr), 1);
                break;
#else
            case ID("Cryptofuzz/Cipher/AES_128_CCM"):
            case ID("Cryptofuzz/Cipher/AES_192_CCM"):
            case ID("Cryptofuzz/Cipher/AES_256_CCM"):
            case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            case ID("Cryptofuzz/Cipher/AES_256_GCM"):
            case ID("Cryptofuzz/Cipher/ARIA_128_CCM"):
            case ID("Cryptofuzz/Cipher/ARIA_192_CCM"):
            case ID("Cryptofuzz/Cipher/ARIA_256_CCM"):
            case ID("Cryptofuzz/Cipher/ARIA_128_GCM"):
            case ID("Cryptofuzz/Cipher/ARIA_192_GCM"):
            case ID("Cryptofuzz/Cipher/ARIA_256_GCM"):
            case ID("Cryptofuzz/Cipher/CHACHA20_POLY1305"):
                CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, inputIvLength, nullptr), 1);
                break;
#endif
            default:
                goto end;
                break;
        }
    }

    ret = true;

end:
    return ret;
}

bool OpenSSL::checkSetKeyLength(const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputKeyLength) const {
    (void)ctx;

    bool ret = false;

    const size_t keyLength = EVP_CIPHER_key_length(cipher);
    if ( keyLength != inputKeyLength ) {
        CF_CHECK_EQ(EVP_CIPHER_CTX_set_key_length(ctx, inputKeyLength), 1);
    }

    ret = true;

end:
    return ret;
}

#if !defined(CRYPTOFUZZ_BORINGSSL)
std::optional<component::Ciphertext> OpenSSL::OpSymmetricEncrypt_BIO(operation::SymmetricEncrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::MAC> ret = std::nullopt;

#if defined(CRYPTOFUZZ_OPENSSL_102)
    using fuzzing::datasource::ID;

    /* These crash in OpenSSL 1.0.2 */
    switch ( op.cipher.cipherType.Get() ) {
        case ID("Cryptofuzz/Cipher/AES_128_WRAP"):
        case ID("Cryptofuzz/Cipher/AES_192_WRAP"):
        case ID("Cryptofuzz/Cipher/AES_256_WRAP"):
        case ID("Cryptofuzz/Cipher/DES_EDE3_WRAP"):
            return ret;
        default:
            break;
    }
#endif

    util::Multipart parts;

    const EVP_CIPHER* cipher = nullptr;
    BIO* bio_cipher = nullptr;

    uint8_t* out = util::malloc(op.ciphertextSize);

    /* Initialization */
    {
        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);

        /* TODO set key/iv size? */
        CF_CHECK_EQ(static_cast<int>(op.cipher.key.GetSize()), EVP_CIPHER_key_length(cipher));
        CF_CHECK_EQ(static_cast<int>(op.cipher.iv.GetSize()), EVP_CIPHER_iv_length(cipher));

        CF_CHECK_NE(bio_cipher = BIO_new(BIO_f_cipher()), nullptr);
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        /* In OpenSSL 1.0.2, BIO_set_cipher does not return a value */
        CF_CHECK_EQ(
#endif
                BIO_set_cipher(bio_cipher, cipher, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), 1 /* encrypt */)
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        , 1)
#endif
           ;
    }

    /* Process */
    {
        BIO_push(bio_cipher, BIO_new_mem_buf(op.cleartext.GetPtr(), op.cleartext.GetSize()));
        //CF_CHECK_EQ(BIO_write(bio_out, op.cleartext.GetPtr(), op.cleartext.GetSize()), static_cast<int>(op.cleartext.GetSize()));
    }

    /* Finalize */
    {
        int num;
        CF_CHECK_GTE(num = BIO_read(bio_cipher, out, op.ciphertextSize), 0);

        /* BIO_read shouldn't report more written bytes than the buffer can hold */
        if ( num > (int)op.ciphertextSize ) {
            goto end;
            abort();
        }

        {
            /* Check if more data can be read. If yes, then the buffer is too small.
             * BIO_eof doesn't seem to work as expected here. */
            int num2;
            uint8_t out2[1];
            CF_CHECK_EQ(num2 = BIO_read(bio_cipher, out2, sizeof(out2)), 0);
        }
        ret = component::Ciphertext(out, num);
    }

end:
    BIO_free_all(bio_cipher);
    util::free(out);

    return ret;
}
#endif

std::optional<component::Ciphertext> OpenSSL::OpSymmetricEncrypt_EVP(operation::SymmetricEncrypt& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    const EVP_CIPHER* cipher = nullptr;
    EVP_CIPHER_CTX* ctx = nullptr;

    size_t out_size = op.ciphertextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);
        CF_CHECK_NE(ctx = EVP_CIPHER_CTX_new(), nullptr);
        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr), 1);

        /* Must be a multiple of the block size of this cipher */
        //CF_CHECK_EQ(op.cleartext.GetSize() % EVP_CIPHER_block_size(cipher), 0);

        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_EQ(checkSetIVLength(op.cipher.cipherType.Get(), cipher, ctx, op.cipher.iv.GetSize()), true);
        CF_CHECK_EQ(checkSetKeyLength(cipher, ctx, op.cipher.key.GetSize()), true);

        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx, nullptr, nullptr, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr()), 1);
    }

    /* Process */
#if 0
    /* Setting AAD */
    {
        int len = -1;
        uint8_t aad[1] = {};
        CF_CHECK_EQ(EVP_EncryptUpdate(ctx, nullptr, &len, aad, 1), 1);
        outIdx += len;
        out_size -= len;
    }
#endif

    for (const auto& part : parts) {
        /* "the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1)" */
        CF_CHECK_GTE(out_size, part.second + EVP_CIPHER_block_size(cipher) - 1);

        int len = -1;
        CF_CHECK_EQ(EVP_EncryptUpdate(ctx, out + outIdx, &len, part.first, part.second), 1);
        outIdx += len;
        out_size -= len;
    }

    /* Finalize */
    {
        CF_CHECK_GTE(out_size, static_cast<size_t>(EVP_CIPHER_block_size(cipher)));

        int len = -1;
        CF_CHECK_EQ(EVP_EncryptFinal_ex(ctx, out + outIdx, &len), 1);
        outIdx += len;

        ret = component::Ciphertext(out, outIdx);
    }

end:
    EVP_CIPHER_CTX_free(ctx);

    util::free(out);

    return ret;
}

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
std::optional<component::Ciphertext> OpenSSL::AEAD_Encrypt(operation::SymmetricEncrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::Ciphertext> ret = std::nullopt;

    const EVP_AEAD* aead = NULL;
    EVP_AEAD_CTX ctx;
    bool ctxInitialized = false;
    size_t len;

    size_t out_size = op.ciphertextSize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(aead = toEVPAEAD(op.cipher.cipherType), nullptr);
        CF_CHECK_NE(EVP_AEAD_CTX_init(&ctx, aead, op.cipher.key.GetPtr(), op.cipher.key.GetSize(), EVP_AEAD_DEFAULT_TAG_LENGTH, NULL), 0);
        ctxInitialized = true;
    }

    /* Process */
    {
        CF_CHECK_NE(EVP_AEAD_CTX_seal(&ctx,
                    out,
                    &len,
                    out_size,
                    op.cipher.iv.GetPtr(),
                    op.cipher.iv.GetSize(),
                    op.cleartext.GetPtr(),
                    op.cleartext.GetSize(),
                    NULL,
                    0),
                0);
    }

    /* Finalize */
    {
        ret = component::Ciphertext(out, len);
    }

end:
    if ( ctxInitialized == true ) {
        EVP_AEAD_CTX_cleanup(&ctx);
    }

    util::free(out);

    return ret;
}
#endif

std::optional<component::Ciphertext> OpenSSL::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
    if ( toEVPAEAD(op.cipher.cipherType) != nullptr ) {
        return AEAD_Encrypt(op, ds);
    }
#endif

    if ( useEVP == true ) {
        return OpSymmetricEncrypt_EVP(op, ds);
    } else {
#if !defined(CRYPTOFUZZ_BORINGSSL)
        return OpSymmetricEncrypt_BIO(op, ds);
#else
        return OpSymmetricEncrypt_EVP(op, ds);
#endif
    }
}

#if !defined(CRYPTOFUZZ_BORINGSSL)
std::optional<component::Ciphertext> OpenSSL::OpSymmetricDecrypt_BIO(operation::SymmetricDecrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::MAC> ret = std::nullopt;

#if defined(CRYPTOFUZZ_OPENSSL_102)
    using fuzzing::datasource::ID;

    /* These crash in OpenSSL 1.0.2 */
    switch ( op.cipher.cipherType.Get() ) {
        case ID("Cryptofuzz/Cipher/AES_128_WRAP"):
        case ID("Cryptofuzz/Cipher/AES_192_WRAP"):
        case ID("Cryptofuzz/Cipher/AES_256_WRAP"):
        case ID("Cryptofuzz/Cipher/DES_EDE3_WRAP"):
            return ret;
        default:
            break;
    }
#endif

    util::Multipart parts;

    const EVP_CIPHER* cipher = nullptr;
    BIO* bio_cipher = nullptr;

    uint8_t* out = util::malloc(op.cleartextSize);

    /* Initialization */
    {
        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);

        /* TODO set key/iv size? */
        CF_CHECK_EQ(static_cast<int>(op.cipher.key.GetSize()), EVP_CIPHER_key_length(cipher));
        CF_CHECK_EQ(static_cast<int>(op.cipher.iv.GetSize()), EVP_CIPHER_iv_length(cipher));

        CF_CHECK_NE(bio_cipher = BIO_new(BIO_f_cipher()), nullptr);
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        /* In OpenSSL 1.0.2, BIO_set_cipher does not return a value */
        CF_CHECK_EQ(
#endif
                BIO_set_cipher(bio_cipher, cipher, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), 0 /* decrypt */)
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        , 1)
#endif
           ;
    }

    /* Process */
    {
        BIO_push(bio_cipher, BIO_new_mem_buf(op.ciphertext.GetPtr(), op.ciphertext.GetSize()));
        //CF_CHECK_EQ(BIO_write(bio_out, op.cleartext.GetPtr(), op.cleartext.GetSize()), static_cast<int>(op.cleartext.GetSize()));
    }

    /* Finalize */
    {
        int num;
        CF_CHECK_GTE(num = BIO_read(bio_cipher, out, op.cleartextSize), 0);

        /* BIO_read shouldn't report more written bytes than the buffer can hold */
        if ( num > (int)op.cleartextSize ) {
            goto end;
            abort();
        }

        {
            /* Check if more data can be read. If yes, then the buffer is too small.
             * BIO_eof doesn't seem to work as expected here. */
            int num2;
            uint8_t out2[1];
            CF_CHECK_EQ(num2 = BIO_read(bio_cipher, out2, sizeof(out2)), 0);
        }
        ret = component::Ciphertext(out, num);
    }

end:
    BIO_free_all(bio_cipher);
    util::free(out);

    return ret;
}
#endif

std::optional<component::Ciphertext> OpenSSL::OpSymmetricDecrypt_EVP(operation::SymmetricDecrypt& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    const EVP_CIPHER* cipher = nullptr;
    EVP_CIPHER_CTX* ctx = nullptr;

    size_t out_size = op.cleartextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);
        CF_CHECK_NE(ctx = EVP_CIPHER_CTX_new(), nullptr);
        CF_CHECK_EQ(EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr), 1);

        /* Must be a multiple of the block size of this cipher */
        //CF_CHECK_EQ(op.ciphertext.GetSize() % EVP_CIPHER_block_size(cipher), 0);

        parts = util::ToParts(ds, op.ciphertext);

        CF_CHECK_EQ(checkSetIVLength(op.cipher.cipherType.Get(), cipher, ctx, op.cipher.iv.GetSize()), true);
        CF_CHECK_EQ(checkSetKeyLength(cipher, ctx, op.cipher.key.GetSize()), true);

        CF_CHECK_EQ(EVP_DecryptInit_ex(ctx, nullptr, nullptr, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr()), 1);
    }

#if 0
    /* Setting AAD */
    {
        int len = -1;
        uint8_t aad[1] = {};
        CF_CHECK_EQ(EVP_DecryptUpdate(ctx, nullptr, &len, aad, 1), 1);
        outIdx += len;
        out_size -= len;
    }
#endif

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_GTE(out_size, part.second + EVP_CIPHER_block_size(cipher));

        int len = -1;
        CF_CHECK_EQ(EVP_DecryptUpdate(ctx, out + outIdx, &len, part.first, part.second), 1);

        outIdx += len;
        out_size -= len;
    }

    /* Finalize */
    {
        CF_CHECK_GTE(out_size, static_cast<size_t>(EVP_CIPHER_block_size(cipher)));

        int len = -1;
        CF_CHECK_EQ(EVP_DecryptFinal_ex(ctx, out + outIdx, &len), 1);
        outIdx += len;

        ret = component::Cleartext(out, outIdx);
    }

end:
    EVP_CIPHER_CTX_free(ctx);

    util::free(out);

    return ret;
}

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
std::optional<component::Cleartext> OpenSSL::AEAD_Decrypt(operation::SymmetricDecrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::Cleartext> ret = std::nullopt;

    const EVP_AEAD* aead = NULL;
    EVP_AEAD_CTX ctx;
    bool ctxInitialized = false;
    size_t len;

    size_t out_size = op.cleartextSize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(aead = toEVPAEAD(op.cipher.cipherType), nullptr);
        CF_CHECK_NE(EVP_AEAD_CTX_init(&ctx, aead, op.cipher.key.GetPtr(), op.cipher.key.GetSize(), EVP_AEAD_DEFAULT_TAG_LENGTH, NULL), 0);
        ctxInitialized = true;
    }

    /* Process */
    {
        CF_CHECK_NE(EVP_AEAD_CTX_open(&ctx,
                    out,
                    &len,
                    out_size,
                    op.cipher.iv.GetPtr(),
                    op.cipher.iv.GetSize(),
                    op.ciphertext.GetPtr(),
                    op.ciphertext.GetSize(),
                    NULL,
                    0),
                0);
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, len);
    }

end:
    if ( ctxInitialized == true ) {
        EVP_AEAD_CTX_cleanup(&ctx);
    }

    util::free(out);

    return ret;
}
#endif

std::optional<component::Cleartext> OpenSSL::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
    if ( toEVPAEAD(op.cipher.cipherType) != nullptr ) {
        return AEAD_Decrypt(op, ds);
    }
#endif

    if ( useEVP == true ) {
        return OpSymmetricDecrypt_EVP(op, ds);
    } else {
#if !defined(CRYPTOFUZZ_BORINGSSL)
        return OpSymmetricDecrypt_BIO(op, ds);
#else
        return OpSymmetricDecrypt_EVP(op, ds);
#endif
    }
}

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
std::optional<component::Key> OpenSSL::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_PKEY_CTX* pctx = nullptr;

    size_t out_size = op.keySize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr), nullptr);
        CF_CHECK_EQ(EVP_PKEY_derive_init(pctx), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set1_pbe_pass(pctx, op.password.GetPtr(), op.password.GetSize()), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set1_scrypt_salt(pctx, op.salt.GetPtr(), op.salt.GetSize()), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_scrypt_N(pctx, op.N) , 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_scrypt_r(pctx, op.r) , 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_scrypt_p(pctx, op.p) , 1);
    }

    /* Process/finalize */
    {
        CF_CHECK_EQ(EVP_PKEY_derive(pctx, out, &out_size) , 1);

        ret = component::Key(out, out_size);
    }

end:
    EVP_PKEY_CTX_free(pctx);
    util::free(out);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
std::optional<component::Key> OpenSSL::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_PKEY_CTX* pctx = nullptr;
    const EVP_MD* md = nullptr;

    size_t out_size = op.keySize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), nullptr);
        CF_CHECK_EQ(EVP_PKEY_derive_init(pctx), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_tls1_prf_md(pctx, md), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set1_hkdf_key(pctx, op.password.GetPtr(), op.password.GetSize()), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set1_hkdf_salt(pctx, op.salt.GetPtr(), op.salt.GetSize()), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_add1_hkdf_info(pctx, op.info.GetPtr(), op.info.GetSize()), 1);
    }

    /* Process/finalize */
    {
        CF_CHECK_EQ(EVP_PKEY_derive(pctx, out, &out_size) , 1);

        ret = component::Key(out, out_size);
    }

end:
    EVP_PKEY_CTX_free(pctx);

    util::free(out);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
std::optional<component::Key> OpenSSL::OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_PKEY_CTX* pctx = nullptr;
    const EVP_MD* md = nullptr;

    size_t out_size = op.keySize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, nullptr), nullptr);
        CF_CHECK_EQ(EVP_PKEY_derive_init(pctx), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_tls1_prf_md(pctx, md), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, op.secret.GetPtr(), op.secret.GetSize()), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, op.seed.GetPtr(), op.seed.GetSize()), 1);
    }

    /* Process/finalize */
    {
        CF_CHECK_EQ(EVP_PKEY_derive(pctx, out, &out_size) , 1);

        ret = component::Key(out, out_size);
    }

end:
    EVP_PKEY_CTX_free(pctx);

    util::free(out);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
std::optional<component::Key> OpenSSL::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_KDF_CTX *kctx = nullptr;
    const EVP_MD* md = nullptr;

    size_t out_size = op.keySize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(kctx = EVP_KDF_CTX_new_id(EVP_KDF_PBKDF2), nullptr);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, op.password.GetPtr(), op.password.GetSize()), 1);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, op.salt.GetPtr(), op.salt.GetSize()), 1);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_ITER, op.iterations), 1);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_MD, md), 1);
    }

    /* Process/finalize */
    {
        CF_CHECK_EQ(EVP_KDF_derive(kctx, out, out_size), 1);

        ret = component::Key(out, out_size);
    }

end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);

    return ret;
}
#endif

std::optional<component::MAC> OpenSSL::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    CMAC_CTX* ctx = nullptr;
    const EVP_CIPHER* cipher = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(ctx = CMAC_CTX_new(), nullptr);
        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);
        CF_CHECK_EQ(CMAC_Init(ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize(), cipher, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(CMAC_Update(ctx, part.first, part.second), 1);
    }

    /* Finalize */
    {
        size_t len = 0;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(CMAC_Final(ctx, out, &len), 1);
        if ( cipher != EVP_aes_128_cbc() ) {
            goto end;
        }
        ret = component::MAC(out, len);
    }

end:
    CMAC_CTX_free(ctx);

    return ret;
}

std::optional<component::Signature> OpenSSL::OpSign(operation::Sign& op) {
    std::optional<component::Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    BIO* bio = nullptr;
    EVP_PKEY* pkey = nullptr;
    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;

    size_t out_size = op.signatureSize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(bio = BIO_new(BIO_s_mem()), nullptr);
        CF_CHECK_EQ(static_cast<size_t>(BIO_write(bio, op.pkeyPEM.GetPtr(), op.pkeyPEM.GetSize())), op.pkeyPEM.GetSize());
        CF_CHECK_NE(pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr), nullptr);

        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(ctx = EVP_MD_CTX_create(), nullptr);
        CF_CHECK_EQ(EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestSignUpdate(ctx, part.first, part.second), 1);
    }

    /* Finalize */
    {
        size_t siglen = 0;
        CF_CHECK_EQ(EVP_DigestSignFinal(ctx, nullptr, &siglen), 1);
        CF_CHECK_GTE(out_size, siglen);
        CF_CHECK_EQ(EVP_DigestSignFinal(ctx, out, &siglen), 1);

        ret = component::Signature(out, siglen);
    }

end:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);

    util::free(out);

    return ret;
}

std::optional<bool> OpenSSL::OpVerify(operation::Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    BIO* bio = nullptr;
    EVP_PKEY* pkey = nullptr;
    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(bio = BIO_new(BIO_s_mem()), nullptr);
        CF_CHECK_EQ(static_cast<size_t>(BIO_write(bio, op.pkeyPEM.GetPtr(), op.pkeyPEM.GetSize())), op.pkeyPEM.GetSize());
        CF_CHECK_NE(pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr), nullptr);

        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(ctx = EVP_MD_CTX_create(), nullptr);
        CF_CHECK_EQ(EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestVerifyUpdate(ctx, part.first, part.second), 1);
    }


    if ( EVP_DigestVerifyFinal(ctx, op.signature.GetPtr(), op.signature.GetSize()) == 1 ) {
        ret = true;
    } else {
        ret = false;
    }

end:
    BIO_free(bio);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_destroy(ctx);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
