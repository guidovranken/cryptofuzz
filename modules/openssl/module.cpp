#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <openssl/aes.h>

#include "module_internal.h"

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
     OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#else
     OpenSSL_add_all_algorithms();
#endif
}


bool OpenSSL::isAEAD(const EVP_CIPHER* ctx) const {
    return EVP_CIPHER_flags(ctx) & EVP_CIPH_FLAG_AEAD_CIPHER;
}

const EVP_MD* OpenSSL::toEVPMD(const component::DigestType& digestType) const {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, const EVP_MD*> LUT = {
#if defined(CRYPTOFUZZ_BORINGSSL)
        { CF_DIGEST("SHA1"), EVP_sha1() },
        { CF_DIGEST("SHA224"), EVP_sha224() },
        { CF_DIGEST("SHA256"), EVP_sha256() },
        { CF_DIGEST("SHA384"), EVP_sha384() },
        { CF_DIGEST("SHA512"), EVP_sha512() },
        { CF_DIGEST("MD4"), EVP_md4() },
        { CF_DIGEST("MD5"), EVP_md5() },
        { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
#elif defined(CRYPTOFUZZ_LIBRESSL)
        { CF_DIGEST("SHA1"), EVP_sha1() },
        { CF_DIGEST("SHA224"), EVP_sha224() },
        { CF_DIGEST("SHA256"), EVP_sha256() },
        { CF_DIGEST("SHA384"), EVP_sha384() },
        { CF_DIGEST("SHA512"), EVP_sha512() },
        { CF_DIGEST("MD4"), EVP_md4() },
        { CF_DIGEST("MD5"), EVP_md5() },
        { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
        { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
        { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
        { CF_DIGEST("SM3"), EVP_sm3() },
        { CF_DIGEST("GOST-R-34.11-94"), EVP_gostr341194() },
        { CF_DIGEST("GOST-28147-89"), EVP_gost2814789imit() },
        { CF_DIGEST("STREEBOG-256"), EVP_streebog256() },
        { CF_DIGEST("STREEBOG-512"), EVP_streebog512() },
#elif defined(CRYPTOFUZZ_OPENSSL_102)
        { CF_DIGEST("SHA1"), EVP_sha1() },
        { CF_DIGEST("SHA224"), EVP_sha224() },
        { CF_DIGEST("SHA256"), EVP_sha256() },
        { CF_DIGEST("SHA384"), EVP_sha384() },
        { CF_DIGEST("SHA512"), EVP_sha512() },
        { CF_DIGEST("MD2"), EVP_md2() },
        { CF_DIGEST("MD4"), EVP_md4() },
        { CF_DIGEST("MD5"), EVP_md5() },
        { CF_DIGEST("MDC2"), EVP_mdc2() },
        { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
        { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
#elif defined(CRYPTOFUZZ_OPENSSL_110)
        { CF_DIGEST("SHA1"), EVP_sha1() },
        { CF_DIGEST("SHA224"), EVP_sha224() },
        { CF_DIGEST("SHA256"), EVP_sha256() },
        { CF_DIGEST("SHA384"), EVP_sha384() },
        { CF_DIGEST("SHA512"), EVP_sha512() },
        { CF_DIGEST("MD2"), EVP_md2() },
        { CF_DIGEST("MD4"), EVP_md4() },
        { CF_DIGEST("MD5"), EVP_md5() },
        { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
        { CF_DIGEST("MDC2"), EVP_mdc2() },
        { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
        { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
        { CF_DIGEST("BLAKE2B512"), EVP_blake2b512() },
        { CF_DIGEST("BLAKE2S256"), EVP_blake2s256() },
#else
        { CF_DIGEST("SHA1"), EVP_sha1() },
        { CF_DIGEST("SHA224"), EVP_sha224() },
        { CF_DIGEST("SHA256"), EVP_sha256() },
        { CF_DIGEST("SHA384"), EVP_sha384() },
        { CF_DIGEST("SHA512"), EVP_sha512() },
        { CF_DIGEST("MD2"), EVP_md2() },
        { CF_DIGEST("MD4"), EVP_md4() },
        { CF_DIGEST("MD5"), EVP_md5() },
        { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
        { CF_DIGEST("MDC2"), EVP_mdc2() },
        { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
        { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
        { CF_DIGEST("SM3"), EVP_sm3() },
        { CF_DIGEST("BLAKE2B512"), EVP_blake2b512() },
        { CF_DIGEST("BLAKE2S256"), EVP_blake2s256() },
        { CF_DIGEST("SHAKE128"), EVP_shake128() },
        { CF_DIGEST("SHAKE256"), EVP_shake256() },
        { CF_DIGEST("SHA3-224"), EVP_sha3_224() },
        { CF_DIGEST("SHA3-256"), EVP_sha3_256() },
        { CF_DIGEST("SHA3-384"), EVP_sha3_384() },
        { CF_DIGEST("SHA3-512"), EVP_sha3_512() },
        { CF_DIGEST("SHA512-224"), EVP_sha512_224() },
        { CF_DIGEST("SHA512-256"), EVP_sha512_256() },
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
        case CF_CIPHER("DES_CBC"):
            return EVP_des_cbc();
        case CF_CIPHER("DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case CF_CIPHER("DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case CF_CIPHER("DES_ECB"):
            return EVP_des_ecb();
        case CF_CIPHER("DES_EDE"):
            return EVP_des_ede();
        case CF_CIPHER("DES_EDE3"):
            return EVP_des_ede3();
        case CF_CIPHER("RC2_CBC"):
            return EVP_rc2_cbc();
        case CF_CIPHER("RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case CF_CIPHER("AES_128_ECB"):
            return EVP_aes_128_ecb();
        case CF_CIPHER("AES_128_CBC"):
            return EVP_aes_128_cbc();
        case CF_CIPHER("AES_128_OFB"):
            return EVP_aes_128_ofb();
        case CF_CIPHER("AES_128_CTR"):
            return EVP_aes_128_ctr();
        case CF_CIPHER("AES_128_GCM"):
            return EVP_aes_128_gcm();
        case CF_CIPHER("AES_192_ECB"):
            return EVP_aes_192_ecb();
        case CF_CIPHER("AES_192_CBC"):
            return EVP_aes_192_cbc();
        case CF_CIPHER("AES_192_OFB"):
            return EVP_aes_192_ofb();
        case CF_CIPHER("AES_192_CTR"):
            return EVP_aes_192_ctr();
        case CF_CIPHER("AES_192_GCM"):
            return EVP_aes_192_gcm();
        case CF_CIPHER("AES_256_ECB"):
            return EVP_aes_256_ecb();
        case CF_CIPHER("AES_256_CBC"):
            return EVP_aes_256_cbc();
        case CF_CIPHER("AES_256_OFB"):
            return EVP_aes_256_ofb();
        case CF_CIPHER("AES_256_CTR"):
            return EVP_aes_256_ctr();
        case CF_CIPHER("AES_256_GCM"):
            return EVP_aes_256_gcm();
        case CF_CIPHER("RC4"):
            return EVP_rc4();
#elif defined(CRYPTOFUZZ_LIBRESSL)
        case CF_CIPHER("DES_CFB"):
            return EVP_des_cfb();
        case CF_CIPHER("DES_CFB1"):
            return EVP_des_cfb1();
        case CF_CIPHER("DES_CFB8"):
            return EVP_des_cfb8();
        case CF_CIPHER("DES_EDE_CFB"):
            return EVP_des_ede_cfb();
        case CF_CIPHER("DES_EDE3_CFB"):
            return EVP_des_ede3_cfb();
        case CF_CIPHER("DES_EDE3_CFB1"):
            return EVP_des_ede3_cfb1();
        case CF_CIPHER("DES_EDE3_CFB8"):
            return EVP_des_ede3_cfb8();
        case CF_CIPHER("DES_OFB"):
            return EVP_des_ofb();
        case CF_CIPHER("DES_EDE_OFB"):
            return EVP_des_ede_ofb();
        case CF_CIPHER("DES_EDE3_OFB"):
            return EVP_des_ede3_ofb();
        case CF_CIPHER("DESX_CBC"):
            return EVP_desx_cbc();
        case CF_CIPHER("DES_CBC"):
            return EVP_des_cbc();
        case CF_CIPHER("DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case CF_CIPHER("DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case CF_CIPHER("DES_ECB"):
            return EVP_des_ecb();
        case CF_CIPHER("DES_EDE"):
            return EVP_des_ede();
        case CF_CIPHER("DES_EDE3"):
            return EVP_des_ede3();
        case CF_CIPHER("RC4"):
            return EVP_rc4();
        case CF_CIPHER("RC4_40"):
            return EVP_rc4_40();
        case CF_CIPHER("RC4_HMAC_MD5"):
            return EVP_rc4_hmac_md5();
        case CF_CIPHER("IDEA_ECB"):
            return EVP_idea_ecb();
        case CF_CIPHER("IDEA_CFB"):
            return EVP_idea_cfb();
        case CF_CIPHER("IDEA_OFB"):
            return EVP_idea_ofb();
        case CF_CIPHER("IDEA_CBC"):
            return EVP_idea_cbc();
        case CF_CIPHER("SM4_ECB"):
            return EVP_sm4_ecb();
        case CF_CIPHER("SM4_CBC"):
            return EVP_sm4_cbc();
        case CF_CIPHER("SM4_CFB"):
            return EVP_sm4_cfb();
        case CF_CIPHER("SM4_OFB"):
            return EVP_sm4_ofb();
        case CF_CIPHER("SM4_CTR"):
            return EVP_sm4_ctr();
        case CF_CIPHER("RC2_ECB"):
            return EVP_rc2_ecb();
        case CF_CIPHER("RC2_CFB"):
            return EVP_rc2_cfb();
        case CF_CIPHER("RC2_OFB"):
            return EVP_rc2_ofb();
        case CF_CIPHER("RC2_CBC"):
            return EVP_rc2_cbc();
        case CF_CIPHER("RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case CF_CIPHER("RC2_64_CBC"):
            return EVP_rc2_64_cbc();
        case CF_CIPHER("BF_ECB"):
            return EVP_bf_ecb();
        case CF_CIPHER("BF_CFB"):
            return EVP_bf_cfb();
        case CF_CIPHER("BF_OFB"):
            return EVP_bf_ofb();
        case CF_CIPHER("BF_CBC"):
            return EVP_bf_cbc();
        case CF_CIPHER("CAST5_ECB"):
            return EVP_cast5_ecb();
        case CF_CIPHER("CAST5_CFB"):
            return EVP_cast5_cfb();
        case CF_CIPHER("CAST5_OFB"):
            return EVP_cast5_ofb();
        case CF_CIPHER("CAST5_CBC"):
            return EVP_cast5_cbc();
        case CF_CIPHER("AES_128_ECB"):
            return EVP_aes_128_ecb();
        case CF_CIPHER("AES_128_CBC"):
            return EVP_aes_128_cbc();
        case CF_CIPHER("AES_128_CFB"):
            return EVP_aes_128_cfb();
        case CF_CIPHER("AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case CF_CIPHER("AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case CF_CIPHER("AES_128_OFB"):
            return EVP_aes_128_ofb();
        case CF_CIPHER("AES_128_CTR"):
            return EVP_aes_128_ctr();
        case CF_CIPHER("AES_128_GCM"):
            return EVP_aes_128_gcm();
        case CF_CIPHER("AES_128_XTS"):
            return EVP_aes_128_xts();
        case CF_CIPHER("AES_128_CCM"):
            return EVP_aes_128_ccm();
        case CF_CIPHER("AES_128_WRAP"):
            return EVP_aes_128_wrap();
        case CF_CIPHER("AES_192_ECB"):
            return EVP_aes_192_ecb();
        case CF_CIPHER("AES_192_CBC"):
            return EVP_aes_192_cbc();
        case CF_CIPHER("AES_192_CFB"):
            return EVP_aes_192_cfb();
        case CF_CIPHER("AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case CF_CIPHER("AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case CF_CIPHER("AES_192_OFB"):
            return EVP_aes_192_ofb();
        case CF_CIPHER("AES_192_CTR"):
            return EVP_aes_192_ctr();
        case CF_CIPHER("AES_192_GCM"):
            return EVP_aes_192_gcm();
        case CF_CIPHER("AES_192_CCM"):
            return EVP_aes_192_ccm();
        case CF_CIPHER("AES_192_WRAP"):
            return EVP_aes_192_wrap();
        case CF_CIPHER("AES_256_ECB"):
            return EVP_aes_256_ecb();
        case CF_CIPHER("AES_256_CBC"):
            return EVP_aes_256_cbc();
        case CF_CIPHER("AES_256_CFB"):
            return EVP_aes_256_cfb();
        case CF_CIPHER("AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case CF_CIPHER("AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case CF_CIPHER("AES_256_OFB"):
            return EVP_aes_256_ofb();
        case CF_CIPHER("AES_256_CTR"):
            return EVP_aes_256_ctr();
        case CF_CIPHER("AES_256_GCM"):
            return EVP_aes_256_gcm();
        case CF_CIPHER("AES_256_XTS"):
            return EVP_aes_256_xts();
        case CF_CIPHER("AES_256_CCM"):
            return EVP_aes_256_ccm();
        case CF_CIPHER("AES_256_WRAP"):
            return EVP_aes_256_wrap();
        case CF_CIPHER("AES_128_CBC_HMAC_SHA1"):
            return EVP_aes_128_cbc_hmac_sha1();
        case CF_CIPHER("AES_256_CBC_HMAC_SHA1"):
            return EVP_aes_256_cbc_hmac_sha1();
        case CF_CIPHER("CAMELLIA_128_ECB"):
            return EVP_camellia_128_ecb();
        case CF_CIPHER("CAMELLIA_128_CBC"):
            return EVP_camellia_128_cbc();
        case CF_CIPHER("CAMELLIA_128_CFB"):
            return EVP_camellia_128_cfb();
        case CF_CIPHER("CAMELLIA_128_CFB1"):
            return EVP_camellia_128_cfb1();
        case CF_CIPHER("CAMELLIA_128_CFB8"):
            return EVP_camellia_128_cfb8();
        case CF_CIPHER("CAMELLIA_128_OFB"):
            return EVP_camellia_128_ofb();
        case CF_CIPHER("CAMELLIA_192_ECB"):
            return EVP_camellia_192_ecb();
        case CF_CIPHER("CAMELLIA_192_CBC"):
            return EVP_camellia_192_cbc();
        case CF_CIPHER("CAMELLIA_192_CFB"):
            return EVP_camellia_192_cfb();
        case CF_CIPHER("CAMELLIA_192_CFB1"):
            return EVP_camellia_192_cfb1();
        case CF_CIPHER("CAMELLIA_192_CFB8"):
            return EVP_camellia_192_cfb8();
        case CF_CIPHER("CAMELLIA_192_OFB"):
            return EVP_camellia_192_ofb();
        case CF_CIPHER("CAMELLIA_256_ECB"):
            return EVP_camellia_256_ecb();
        case CF_CIPHER("CAMELLIA_256_CBC"):
            return EVP_camellia_256_cbc();
        case CF_CIPHER("CAMELLIA_256_CFB"):
            return EVP_camellia_256_cfb();
        case CF_CIPHER("CAMELLIA_256_CFB1"):
            return EVP_camellia_256_cfb1();
        case CF_CIPHER("CAMELLIA_256_CFB8"):
            return EVP_camellia_256_cfb8();
        case CF_CIPHER("CAMELLIA_256_OFB"):
            return EVP_camellia_256_ofb();
        case CF_CIPHER("CHACHA20"):
            return EVP_chacha20();
#elif defined(CRYPTOFUZZ_OPENSSL_102)
        case CF_CIPHER("DES_CFB"):
            return EVP_des_cfb();
        case CF_CIPHER("DES_CFB1"):
            return EVP_des_cfb1();
        case CF_CIPHER("DES_CFB8"):
            return EVP_des_cfb8();
        case CF_CIPHER("DES_EDE_CFB"):
            return EVP_des_ede_cfb();
        case CF_CIPHER("DES_EDE3_CFB"):
            return EVP_des_ede3_cfb();
        case CF_CIPHER("DES_EDE3_CFB1"):
            return EVP_des_ede3_cfb1();
        case CF_CIPHER("DES_EDE3_CFB8"):
            return EVP_des_ede3_cfb8();
        case CF_CIPHER("DES_OFB"):
            return EVP_des_ofb();
        case CF_CIPHER("DES_EDE_OFB"):
            return EVP_des_ede_ofb();
        case CF_CIPHER("DES_EDE3_OFB"):
            return EVP_des_ede3_ofb();
        case CF_CIPHER("DESX_CBC"):
            return EVP_desx_cbc();
        case CF_CIPHER("DES_CBC"):
            return EVP_des_cbc();
        case CF_CIPHER("DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case CF_CIPHER("DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case CF_CIPHER("DES_ECB"):
            return EVP_des_ecb();
        case CF_CIPHER("DES_EDE"):
            return EVP_des_ede();
        case CF_CIPHER("DES_EDE3"):
            return EVP_des_ede3();
        case CF_CIPHER("DES_EDE3_WRAP"):
            return EVP_des_ede3_wrap();
        case CF_CIPHER("RC4"):
            return EVP_rc4();
        case CF_CIPHER("RC4_40"):
            return EVP_rc4_40();
        case CF_CIPHER("RC4_HMAC_MD5"):
            return EVP_rc4_hmac_md5();
        case CF_CIPHER("IDEA_ECB"):
            return EVP_idea_ecb();
        case CF_CIPHER("IDEA_CFB"):
            return EVP_idea_cfb();
        case CF_CIPHER("IDEA_OFB"):
            return EVP_idea_ofb();
        case CF_CIPHER("IDEA_CBC"):
            return EVP_idea_cbc();
        case CF_CIPHER("SEED_ECB"):
            return EVP_seed_ecb();
        case CF_CIPHER("SEED_CFB"):
            return EVP_seed_cfb();
        case CF_CIPHER("SEED_OFB"):
            return EVP_seed_ofb();
        case CF_CIPHER("SEED_CBC"):
            return EVP_seed_cbc();
        case CF_CIPHER("RC2_ECB"):
            return EVP_rc2_ecb();
        case CF_CIPHER("RC2_CFB"):
            return EVP_rc2_cfb();
        case CF_CIPHER("RC2_OFB"):
            return EVP_rc2_ofb();
        case CF_CIPHER("RC2_CBC"):
            return EVP_rc2_cbc();
        case CF_CIPHER("RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case CF_CIPHER("RC2_64_CBC"):
            return EVP_rc2_64_cbc();
        case CF_CIPHER("BF_ECB"):
            return EVP_bf_ecb();
        case CF_CIPHER("BF_CFB"):
            return EVP_bf_cfb();
        case CF_CIPHER("BF_OFB"):
            return EVP_bf_ofb();
        case CF_CIPHER("BF_CBC"):
            return EVP_bf_cbc();
        case CF_CIPHER("CAST5_ECB"):
            return EVP_cast5_ecb();
        case CF_CIPHER("CAST5_CFB"):
            return EVP_cast5_cfb();
        case CF_CIPHER("CAST5_OFB"):
            return EVP_cast5_ofb();
        case CF_CIPHER("CAST5_CBC"):
            return EVP_cast5_cbc();
        case CF_CIPHER("RC5_32_12_16_ECB"):
            return EVP_rc5_32_12_16_ecb();
        case CF_CIPHER("RC5_32_12_16_CFB"):
            return EVP_rc5_32_12_16_cfb();
        case CF_CIPHER("RC5_32_12_16_OFB"):
            return EVP_rc5_32_12_16_ofb();
        case CF_CIPHER("RC5_32_12_16_CBC"):
            return EVP_rc5_32_12_16_cbc();
        case CF_CIPHER("AES_128_ECB"):
            return EVP_aes_128_ecb();
        case CF_CIPHER("AES_128_CBC"):
            return EVP_aes_128_cbc();
        case CF_CIPHER("AES_128_CFB"):
            return EVP_aes_128_cfb();
        case CF_CIPHER("AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case CF_CIPHER("AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case CF_CIPHER("AES_128_OFB"):
            return EVP_aes_128_ofb();
        case CF_CIPHER("AES_128_CTR"):
            return EVP_aes_128_ctr();
        case CF_CIPHER("AES_128_GCM"):
            return EVP_aes_128_gcm();
        case CF_CIPHER("AES_128_XTS"):
            return EVP_aes_128_xts();
        case CF_CIPHER("AES_128_CCM"):
            return EVP_aes_128_ccm();
        case CF_CIPHER("AES_128_WRAP"):
            return EVP_aes_128_wrap();
        case CF_CIPHER("AES_192_ECB"):
            return EVP_aes_192_ecb();
        case CF_CIPHER("AES_192_CBC"):
            return EVP_aes_192_cbc();
        case CF_CIPHER("AES_192_CFB"):
            return EVP_aes_192_cfb();
        case CF_CIPHER("AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case CF_CIPHER("AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case CF_CIPHER("AES_192_OFB"):
            return EVP_aes_192_ofb();
        case CF_CIPHER("AES_192_CTR"):
            return EVP_aes_192_ctr();
        case CF_CIPHER("AES_192_GCM"):
            return EVP_aes_192_gcm();
        case CF_CIPHER("AES_192_CCM"):
            return EVP_aes_192_ccm();
        case CF_CIPHER("AES_192_WRAP"):
            return EVP_aes_192_wrap();
        case CF_CIPHER("AES_256_ECB"):
            return EVP_aes_256_ecb();
        case CF_CIPHER("AES_256_CBC"):
            return EVP_aes_256_cbc();
        case CF_CIPHER("AES_256_CFB"):
            return EVP_aes_256_cfb();
        case CF_CIPHER("AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case CF_CIPHER("AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case CF_CIPHER("AES_256_OFB"):
            return EVP_aes_256_ofb();
        case CF_CIPHER("AES_256_CTR"):
            return EVP_aes_256_ctr();
        case CF_CIPHER("AES_256_GCM"):
            return EVP_aes_256_gcm();
        case CF_CIPHER("AES_256_XTS"):
            return EVP_aes_256_xts();
        case CF_CIPHER("AES_256_CCM"):
            return EVP_aes_256_ccm();
        case CF_CIPHER("AES_256_WRAP"):
            return EVP_aes_256_wrap();
        case CF_CIPHER("AES_128_CBC_HMAC_SHA1"):
            return EVP_aes_128_cbc_hmac_sha1();
        case CF_CIPHER("AES_256_CBC_HMAC_SHA1"):
            return EVP_aes_256_cbc_hmac_sha1();
        case CF_CIPHER("AES_128_CBC_HMAC_SHA256"):
            return EVP_aes_128_cbc_hmac_sha256();
        case CF_CIPHER("AES_256_CBC_HMAC_SHA256"):
            return EVP_aes_256_cbc_hmac_sha256();
        case CF_CIPHER("CAMELLIA_128_ECB"):
            return EVP_camellia_128_ecb();
        case CF_CIPHER("CAMELLIA_128_CBC"):
            return EVP_camellia_128_cbc();
        case CF_CIPHER("CAMELLIA_128_CFB"):
            return EVP_camellia_128_cfb();
        case CF_CIPHER("CAMELLIA_128_CFB1"):
            return EVP_camellia_128_cfb1();
        case CF_CIPHER("CAMELLIA_128_CFB8"):
            return EVP_camellia_128_cfb8();
        case CF_CIPHER("CAMELLIA_128_OFB"):
            return EVP_camellia_128_ofb();
        case CF_CIPHER("CAMELLIA_192_ECB"):
            return EVP_camellia_192_ecb();
        case CF_CIPHER("CAMELLIA_192_CBC"):
            return EVP_camellia_192_cbc();
        case CF_CIPHER("CAMELLIA_192_CFB"):
            return EVP_camellia_192_cfb();
        case CF_CIPHER("CAMELLIA_192_CFB1"):
            return EVP_camellia_192_cfb1();
        case CF_CIPHER("CAMELLIA_192_CFB8"):
            return EVP_camellia_192_cfb8();
        case CF_CIPHER("CAMELLIA_192_OFB"):
            return EVP_camellia_192_ofb();
        case CF_CIPHER("CAMELLIA_256_ECB"):
            return EVP_camellia_256_ecb();
        case CF_CIPHER("CAMELLIA_256_CBC"):
            return EVP_camellia_256_cbc();
        case CF_CIPHER("CAMELLIA_256_CFB"):
            return EVP_camellia_256_cfb();
        case CF_CIPHER("CAMELLIA_256_CFB1"):
            return EVP_camellia_256_cfb1();
        case CF_CIPHER("CAMELLIA_256_CFB8"):
            return EVP_camellia_256_cfb8();
        case CF_CIPHER("CAMELLIA_256_OFB"):
            return EVP_camellia_256_ofb();
#elif defined(CRYPTOFUZZ_OPENSSL_110)
        case CF_CIPHER("DES_CFB"):
            return EVP_des_cfb();
        case CF_CIPHER("DES_CFB1"):
            return EVP_des_cfb1();
        case CF_CIPHER("DES_CFB8"):
            return EVP_des_cfb8();
        case CF_CIPHER("DES_EDE_CFB"):
            return EVP_des_ede_cfb();
        case CF_CIPHER("DES_EDE3_CFB"):
            return EVP_des_ede3_cfb();
        case CF_CIPHER("DES_EDE3_CFB1"):
            return EVP_des_ede3_cfb1();
        case CF_CIPHER("DES_EDE3_CFB8"):
            return EVP_des_ede3_cfb8();
        case CF_CIPHER("DES_OFB"):
            return EVP_des_ofb();
        case CF_CIPHER("DES_EDE_OFB"):
            return EVP_des_ede_ofb();
        case CF_CIPHER("DES_EDE3_OFB"):
            return EVP_des_ede3_ofb();
        case CF_CIPHER("DESX_CBC"):
            return EVP_desx_cbc();
        case CF_CIPHER("DES_CBC"):
            return EVP_des_cbc();
        case CF_CIPHER("DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case CF_CIPHER("DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case CF_CIPHER("DES_ECB"):
            return EVP_des_ecb();
        case CF_CIPHER("DES_EDE"):
            return EVP_des_ede();
        case CF_CIPHER("DES_EDE3"):
            return EVP_des_ede3();
        case CF_CIPHER("DES_EDE3_WRAP"):
            return EVP_des_ede3_wrap();
        case CF_CIPHER("RC4"):
            return EVP_rc4();
        case CF_CIPHER("RC4_40"):
            return EVP_rc4_40();
        case CF_CIPHER("RC4_HMAC_MD5"):
            return EVP_rc4_hmac_md5();
        case CF_CIPHER("IDEA_ECB"):
            return EVP_idea_ecb();
        case CF_CIPHER("IDEA_CFB"):
            return EVP_idea_cfb();
        case CF_CIPHER("IDEA_OFB"):
            return EVP_idea_ofb();
        case CF_CIPHER("IDEA_CBC"):
            return EVP_idea_cbc();
        case CF_CIPHER("SEED_ECB"):
            return EVP_seed_ecb();
        case CF_CIPHER("SEED_CFB"):
            return EVP_seed_cfb();
        case CF_CIPHER("SEED_OFB"):
            return EVP_seed_ofb();
        case CF_CIPHER("SEED_CBC"):
            return EVP_seed_cbc();
        case CF_CIPHER("RC2_ECB"):
            return EVP_rc2_ecb();
        case CF_CIPHER("RC2_CFB"):
            return EVP_rc2_cfb();
        case CF_CIPHER("RC2_OFB"):
            return EVP_rc2_ofb();
        case CF_CIPHER("RC2_CBC"):
            return EVP_rc2_cbc();
        case CF_CIPHER("RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case CF_CIPHER("RC2_64_CBC"):
            return EVP_rc2_64_cbc();
        case CF_CIPHER("BF_ECB"):
            return EVP_bf_ecb();
        case CF_CIPHER("BF_CFB"):
            return EVP_bf_cfb();
        case CF_CIPHER("BF_OFB"):
            return EVP_bf_ofb();
        case CF_CIPHER("BF_CBC"):
            return EVP_bf_cbc();
        case CF_CIPHER("CAST5_ECB"):
            return EVP_cast5_ecb();
        case CF_CIPHER("CAST5_CFB"):
            return EVP_cast5_cfb();
        case CF_CIPHER("CAST5_OFB"):
            return EVP_cast5_ofb();
        case CF_CIPHER("CAST5_CBC"):
            return EVP_cast5_cbc();
        case CF_CIPHER("RC5_32_12_16_ECB"):
            return EVP_rc5_32_12_16_ecb();
        case CF_CIPHER("RC5_32_12_16_CFB"):
            return EVP_rc5_32_12_16_cfb();
        case CF_CIPHER("RC5_32_12_16_OFB"):
            return EVP_rc5_32_12_16_ofb();
        case CF_CIPHER("RC5_32_12_16_CBC"):
            return EVP_rc5_32_12_16_cbc();
        case CF_CIPHER("AES_128_ECB"):
            return EVP_aes_128_ecb();
        case CF_CIPHER("AES_128_CBC"):
            return EVP_aes_128_cbc();
        case CF_CIPHER("AES_128_CFB"):
            return EVP_aes_128_cfb();
        case CF_CIPHER("AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case CF_CIPHER("AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case CF_CIPHER("AES_128_OFB"):
            return EVP_aes_128_ofb();
        case CF_CIPHER("AES_128_CTR"):
            return EVP_aes_128_ctr();
        case CF_CIPHER("AES_128_GCM"):
            return EVP_aes_128_gcm();
        case CF_CIPHER("AES_128_OCB"):
            return EVP_aes_128_ocb();
        case CF_CIPHER("AES_128_XTS"):
            return EVP_aes_128_xts();
        case CF_CIPHER("AES_128_CCM"):
            return EVP_aes_128_ccm();
        case CF_CIPHER("AES_128_WRAP"):
            return EVP_aes_128_wrap();
        case CF_CIPHER("AES_128_WRAP_PAD"):
            return EVP_aes_128_wrap_pad();
        case CF_CIPHER("AES_192_ECB"):
            return EVP_aes_192_ecb();
        case CF_CIPHER("AES_192_CBC"):
            return EVP_aes_192_cbc();
        case CF_CIPHER("AES_192_CFB"):
            return EVP_aes_192_cfb();
        case CF_CIPHER("AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case CF_CIPHER("AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case CF_CIPHER("AES_192_OFB"):
            return EVP_aes_192_ofb();
        case CF_CIPHER("AES_192_CTR"):
            return EVP_aes_192_ctr();
        case CF_CIPHER("AES_192_GCM"):
            return EVP_aes_192_gcm();
        case CF_CIPHER("AES_192_CCM"):
            return EVP_aes_192_ccm();
        case CF_CIPHER("AES_192_WRAP"):
            return EVP_aes_192_wrap();
        case CF_CIPHER("AES_192_WRAP_PAD"):
            return EVP_aes_192_wrap_pad();
        case CF_CIPHER("AES_256_ECB"):
            return EVP_aes_256_ecb();
        case CF_CIPHER("AES_256_CBC"):
            return EVP_aes_256_cbc();
        case CF_CIPHER("AES_256_CFB"):
            return EVP_aes_256_cfb();
        case CF_CIPHER("AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case CF_CIPHER("AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case CF_CIPHER("AES_256_OFB"):
            return EVP_aes_256_ofb();
        case CF_CIPHER("AES_256_CTR"):
            return EVP_aes_256_ctr();
        case CF_CIPHER("AES_256_GCM"):
            return EVP_aes_256_gcm();
        case CF_CIPHER("AES_256_OCB"):
            return EVP_aes_256_ocb();
        case CF_CIPHER("AES_256_XTS"):
            return EVP_aes_256_xts();
        case CF_CIPHER("AES_256_CCM"):
            return EVP_aes_256_ccm();
        case CF_CIPHER("AES_256_WRAP"):
            return EVP_aes_256_wrap();
        case CF_CIPHER("AES_256_WRAP_PAD"):
            return EVP_aes_256_wrap_pad();
        case CF_CIPHER("AES_128_CBC_HMAC_SHA1"):
            return EVP_aes_128_cbc_hmac_sha1();
        case CF_CIPHER("AES_256_CBC_HMAC_SHA1"):
            return EVP_aes_256_cbc_hmac_sha1();
        case CF_CIPHER("AES_128_CBC_HMAC_SHA256"):
            return EVP_aes_128_cbc_hmac_sha256();
        case CF_CIPHER("AES_256_CBC_HMAC_SHA256"):
            return EVP_aes_256_cbc_hmac_sha256();
        case CF_CIPHER("CAMELLIA_128_ECB"):
            return EVP_camellia_128_ecb();
        case CF_CIPHER("CAMELLIA_128_CBC"):
            return EVP_camellia_128_cbc();
        case CF_CIPHER("CAMELLIA_128_CFB"):
            return EVP_camellia_128_cfb();
        case CF_CIPHER("CAMELLIA_128_CFB1"):
            return EVP_camellia_128_cfb1();
        case CF_CIPHER("CAMELLIA_128_CFB8"):
            return EVP_camellia_128_cfb8();
        case CF_CIPHER("CAMELLIA_128_OFB"):
            return EVP_camellia_128_ofb();
        case CF_CIPHER("CAMELLIA_192_ECB"):
            return EVP_camellia_192_ecb();
        case CF_CIPHER("CAMELLIA_192_CBC"):
            return EVP_camellia_192_cbc();
        case CF_CIPHER("CAMELLIA_192_CFB"):
            return EVP_camellia_192_cfb();
        case CF_CIPHER("CAMELLIA_192_CFB1"):
            return EVP_camellia_192_cfb1();
        case CF_CIPHER("CAMELLIA_192_CFB8"):
            return EVP_camellia_192_cfb8();
        case CF_CIPHER("CAMELLIA_192_OFB"):
            return EVP_camellia_192_ofb();
        case CF_CIPHER("CAMELLIA_256_ECB"):
            return EVP_camellia_256_ecb();
        case CF_CIPHER("CAMELLIA_256_CBC"):
            return EVP_camellia_256_cbc();
        case CF_CIPHER("CAMELLIA_256_CFB"):
            return EVP_camellia_256_cfb();
        case CF_CIPHER("CAMELLIA_256_CFB1"):
            return EVP_camellia_256_cfb1();
        case CF_CIPHER("CAMELLIA_256_CFB8"):
            return EVP_camellia_256_cfb8();
        case CF_CIPHER("CAMELLIA_256_OFB"):
            return EVP_camellia_256_ofb();
        case CF_CIPHER("CAMELLIA_128_CTR"):
            return EVP_camellia_128_ctr();
        case CF_CIPHER("CAMELLIA_192_CTR"):
            return EVP_camellia_192_ctr();
        case CF_CIPHER("CAMELLIA_256_CTR"):
            return EVP_camellia_256_ctr();
        case CF_CIPHER("CHACHA20"):
            return EVP_chacha20();
        case CF_CIPHER("CHACHA20_POLY1305"):
            return EVP_chacha20_poly1305();
#else
        case CF_CIPHER("DES_CFB"):
            return EVP_des_cfb();
        case CF_CIPHER("DES_CFB1"):
            return EVP_des_cfb1();
        case CF_CIPHER("DES_CFB8"):
            return EVP_des_cfb8();
        case CF_CIPHER("DES_EDE_CFB"):
            return EVP_des_ede_cfb();
        case CF_CIPHER("DES_EDE3_CFB"):
            return EVP_des_ede3_cfb();
        case CF_CIPHER("DES_EDE3_CFB1"):
            return EVP_des_ede3_cfb1();
        case CF_CIPHER("DES_EDE3_CFB8"):
            return EVP_des_ede3_cfb8();
        case CF_CIPHER("DES_OFB"):
            return EVP_des_ofb();
        case CF_CIPHER("DES_EDE_OFB"):
            return EVP_des_ede_ofb();
        case CF_CIPHER("DES_EDE3_OFB"):
            return EVP_des_ede3_ofb();
        case CF_CIPHER("DESX_CBC"):
            return EVP_desx_cbc();
        case CF_CIPHER("DES_CBC"):
            return EVP_des_cbc();
        case CF_CIPHER("DES_EDE_CBC"):
            return EVP_des_ede_cbc();
        case CF_CIPHER("DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case CF_CIPHER("DES_ECB"):
            return EVP_des_ecb();
        case CF_CIPHER("DES_EDE"):
            return EVP_des_ede();
        case CF_CIPHER("DES_EDE3"):
            return EVP_des_ede3();
        case CF_CIPHER("DES_EDE3_WRAP"):
            return EVP_des_ede3_wrap();
        case CF_CIPHER("RC4"):
            return EVP_rc4();
        case CF_CIPHER("RC4_40"):
            return EVP_rc4_40();
        case CF_CIPHER("RC4_HMAC_MD5"):
            return EVP_rc4_hmac_md5();
        case CF_CIPHER("IDEA_ECB"):
            return EVP_idea_ecb();
        case CF_CIPHER("IDEA_CFB"):
            return EVP_idea_cfb();
        case CF_CIPHER("IDEA_OFB"):
            return EVP_idea_ofb();
        case CF_CIPHER("IDEA_CBC"):
            return EVP_idea_cbc();
        case CF_CIPHER("SEED_ECB"):
            return EVP_seed_ecb();
        case CF_CIPHER("SEED_CFB"):
            return EVP_seed_cfb();
        case CF_CIPHER("SEED_OFB"):
            return EVP_seed_ofb();
        case CF_CIPHER("SEED_CBC"):
            return EVP_seed_cbc();
        case CF_CIPHER("SM4_ECB"):
            return EVP_sm4_ecb();
        case CF_CIPHER("SM4_CBC"):
            return EVP_sm4_cbc();
        case CF_CIPHER("SM4_CFB"):
            return EVP_sm4_cfb();
        case CF_CIPHER("SM4_OFB"):
            return EVP_sm4_ofb();
        case CF_CIPHER("SM4_CTR"):
            return EVP_sm4_ctr();
        case CF_CIPHER("RC2_ECB"):
            return EVP_rc2_ecb();
        case CF_CIPHER("RC2_CFB"):
            return EVP_rc2_cfb();
        case CF_CIPHER("RC2_OFB"):
            return EVP_rc2_ofb();
        case CF_CIPHER("RC2_CBC"):
            return EVP_rc2_cbc();
        case CF_CIPHER("RC2_40_CBC"):
            return EVP_rc2_40_cbc();
        case CF_CIPHER("RC2_64_CBC"):
            return EVP_rc2_64_cbc();
        case CF_CIPHER("BF_ECB"):
            return EVP_bf_ecb();
        case CF_CIPHER("BF_CFB"):
            return EVP_bf_cfb();
        case CF_CIPHER("BF_OFB"):
            return EVP_bf_ofb();
        case CF_CIPHER("BF_CBC"):
            return EVP_bf_cbc();
        case CF_CIPHER("CAST5_ECB"):
            return EVP_cast5_ecb();
        case CF_CIPHER("CAST5_CFB"):
            return EVP_cast5_cfb();
        case CF_CIPHER("CAST5_OFB"):
            return EVP_cast5_ofb();
        case CF_CIPHER("CAST5_CBC"):
            return EVP_cast5_cbc();
        case CF_CIPHER("RC5_32_12_16_ECB"):
            return EVP_rc5_32_12_16_ecb();
        case CF_CIPHER("RC5_32_12_16_CFB"):
            return EVP_rc5_32_12_16_cfb();
        case CF_CIPHER("RC5_32_12_16_OFB"):
            return EVP_rc5_32_12_16_ofb();
        case CF_CIPHER("RC5_32_12_16_CBC"):
            return EVP_rc5_32_12_16_cbc();
        case CF_CIPHER("AES_128_ECB"):
            return EVP_aes_128_ecb();
        case CF_CIPHER("AES_128_CBC"):
            return EVP_aes_128_cbc();
        case CF_CIPHER("AES_128_CFB"):
            return EVP_aes_128_cfb();
        case CF_CIPHER("AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case CF_CIPHER("AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case CF_CIPHER("AES_128_OFB"):
            return EVP_aes_128_ofb();
        case CF_CIPHER("AES_128_CTR"):
            return EVP_aes_128_ctr();
        case CF_CIPHER("AES_128_GCM"):
            return EVP_aes_128_gcm();
        case CF_CIPHER("AES_128_OCB"):
            return EVP_aes_128_ocb();
        case CF_CIPHER("AES_128_XTS"):
            return EVP_aes_128_xts();
        case CF_CIPHER("AES_128_CCM"):
            return EVP_aes_128_ccm();
        case CF_CIPHER("AES_128_WRAP"):
            return EVP_aes_128_wrap();
        case CF_CIPHER("AES_128_WRAP_PAD"):
            return EVP_aes_128_wrap_pad();
        case CF_CIPHER("AES_192_ECB"):
            return EVP_aes_192_ecb();
        case CF_CIPHER("AES_192_CBC"):
            return EVP_aes_192_cbc();
        case CF_CIPHER("AES_192_CFB"):
            return EVP_aes_192_cfb();
        case CF_CIPHER("AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case CF_CIPHER("AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case CF_CIPHER("AES_192_OFB"):
            return EVP_aes_192_ofb();
        case CF_CIPHER("AES_192_CTR"):
            return EVP_aes_192_ctr();
        case CF_CIPHER("AES_192_GCM"):
            return EVP_aes_192_gcm();
        case CF_CIPHER("AES_192_CCM"):
            return EVP_aes_192_ccm();
        case CF_CIPHER("AES_192_WRAP"):
            return EVP_aes_192_wrap();
        case CF_CIPHER("AES_192_WRAP_PAD"):
            return EVP_aes_192_wrap_pad();
        case CF_CIPHER("AES_256_ECB"):
            return EVP_aes_256_ecb();
        case CF_CIPHER("AES_256_CBC"):
            return EVP_aes_256_cbc();
        case CF_CIPHER("AES_256_CFB"):
            return EVP_aes_256_cfb();
        case CF_CIPHER("AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case CF_CIPHER("AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case CF_CIPHER("AES_256_OFB"):
            return EVP_aes_256_ofb();
        case CF_CIPHER("AES_256_CTR"):
            return EVP_aes_256_ctr();
        case CF_CIPHER("AES_256_GCM"):
            return EVP_aes_256_gcm();
        case CF_CIPHER("AES_256_OCB"):
            return EVP_aes_256_ocb();
        case CF_CIPHER("AES_256_XTS"):
            return EVP_aes_256_xts();
        case CF_CIPHER("AES_256_CCM"):
            return EVP_aes_256_ccm();
        case CF_CIPHER("AES_256_WRAP"):
            return EVP_aes_256_wrap();
        case CF_CIPHER("AES_256_WRAP_PAD"):
            return EVP_aes_256_wrap_pad();
        case CF_CIPHER("AES_128_CBC_HMAC_SHA1"):
            return EVP_aes_128_cbc_hmac_sha1();
        case CF_CIPHER("AES_256_CBC_HMAC_SHA1"):
            return EVP_aes_256_cbc_hmac_sha1();
        case CF_CIPHER("AES_128_CBC_HMAC_SHA256"):
            return EVP_aes_128_cbc_hmac_sha256();
        case CF_CIPHER("AES_256_CBC_HMAC_SHA256"):
            return EVP_aes_256_cbc_hmac_sha256();
        case CF_CIPHER("ARIA_128_ECB"):
            return EVP_aria_128_ecb();
        case CF_CIPHER("ARIA_128_CBC"):
            return EVP_aria_128_cbc();
        case CF_CIPHER("ARIA_128_CFB"):
            return EVP_aria_128_cfb();
        case CF_CIPHER("ARIA_128_CFB1"):
            return EVP_aria_128_cfb1();
        case CF_CIPHER("ARIA_128_CFB8"):
            return EVP_aria_128_cfb8();
        case CF_CIPHER("ARIA_128_CTR"):
            return EVP_aria_128_ctr();
        case CF_CIPHER("ARIA_128_OFB"):
            return EVP_aria_128_ofb();
        case CF_CIPHER("ARIA_128_GCM"):
            return EVP_aria_128_gcm();
        case CF_CIPHER("ARIA_128_CCM"):
            return EVP_aria_128_ccm();
        case CF_CIPHER("ARIA_192_ECB"):
            return EVP_aria_192_ecb();
        case CF_CIPHER("ARIA_192_CBC"):
            return EVP_aria_192_cbc();
        case CF_CIPHER("ARIA_192_CFB"):
            return EVP_aria_192_cfb();
        case CF_CIPHER("ARIA_192_CFB1"):
            return EVP_aria_192_cfb1();
        case CF_CIPHER("ARIA_192_CFB8"):
            return EVP_aria_192_cfb8();
        case CF_CIPHER("ARIA_192_CTR"):
            return EVP_aria_192_ctr();
        case CF_CIPHER("ARIA_192_OFB"):
            return EVP_aria_192_ofb();
        case CF_CIPHER("ARIA_192_GCM"):
            return EVP_aria_192_gcm();
        case CF_CIPHER("ARIA_192_CCM"):
            return EVP_aria_192_ccm();
        case CF_CIPHER("ARIA_256_ECB"):
            return EVP_aria_256_ecb();
        case CF_CIPHER("ARIA_256_CBC"):
            return EVP_aria_256_cbc();
        case CF_CIPHER("ARIA_256_CFB"):
            return EVP_aria_256_cfb();
        case CF_CIPHER("ARIA_256_CFB1"):
            return EVP_aria_256_cfb1();
        case CF_CIPHER("ARIA_256_CFB8"):
            return EVP_aria_256_cfb8();
        case CF_CIPHER("ARIA_256_CTR"):
            return EVP_aria_256_ctr();
        case CF_CIPHER("ARIA_256_OFB"):
            return EVP_aria_256_ofb();
        case CF_CIPHER("ARIA_256_GCM"):
            return EVP_aria_256_gcm();
        case CF_CIPHER("ARIA_256_CCM"):
            return EVP_aria_256_ccm();
        case CF_CIPHER("CAMELLIA_128_ECB"):
            return EVP_camellia_128_ecb();
        case CF_CIPHER("CAMELLIA_128_CBC"):
            return EVP_camellia_128_cbc();
        case CF_CIPHER("CAMELLIA_128_CFB"):
            return EVP_camellia_128_cfb();
        case CF_CIPHER("CAMELLIA_128_CFB1"):
            return EVP_camellia_128_cfb1();
        case CF_CIPHER("CAMELLIA_128_CFB8"):
            return EVP_camellia_128_cfb8();
        case CF_CIPHER("CAMELLIA_128_OFB"):
            return EVP_camellia_128_ofb();
        case CF_CIPHER("CAMELLIA_192_ECB"):
            return EVP_camellia_192_ecb();
        case CF_CIPHER("CAMELLIA_192_CBC"):
            return EVP_camellia_192_cbc();
        case CF_CIPHER("CAMELLIA_192_CFB"):
            return EVP_camellia_192_cfb();
        case CF_CIPHER("CAMELLIA_192_CFB1"):
            return EVP_camellia_192_cfb1();
        case CF_CIPHER("CAMELLIA_192_CFB8"):
            return EVP_camellia_192_cfb8();
        case CF_CIPHER("CAMELLIA_192_OFB"):
            return EVP_camellia_192_ofb();
        case CF_CIPHER("CAMELLIA_256_ECB"):
            return EVP_camellia_256_ecb();
        case CF_CIPHER("CAMELLIA_256_CBC"):
            return EVP_camellia_256_cbc();
        case CF_CIPHER("CAMELLIA_256_CFB"):
            return EVP_camellia_256_cfb();
        case CF_CIPHER("CAMELLIA_256_CFB1"):
            return EVP_camellia_256_cfb1();
        case CF_CIPHER("CAMELLIA_256_CFB8"):
            return EVP_camellia_256_cfb8();
        case CF_CIPHER("CAMELLIA_256_OFB"):
            return EVP_camellia_256_ofb();
        case CF_CIPHER("CAMELLIA_128_CTR"):
            return EVP_camellia_128_ctr();
        case CF_CIPHER("CAMELLIA_192_CTR"):
            return EVP_camellia_192_ctr();
        case CF_CIPHER("CAMELLIA_256_CTR"):
            return EVP_camellia_256_ctr();
        case CF_CIPHER("CHACHA20"):
            return EVP_chacha20();
        case CF_CIPHER("CHACHA20_POLY1305"):
            return EVP_chacha20_poly1305();
#endif
        default:
            return nullptr;
    }
}

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
const EVP_AEAD* OpenSSL::toEVPAEAD(const component::SymmetricCipherType cipherType) const {
    static const std::map<uint64_t, const EVP_AEAD*> LUT = {
        { CF_CIPHER("CHACHA20_POLY1305"), EVP_aead_chacha20_poly1305() },
        { CF_CIPHER("XCHACHA20_POLY1305"), EVP_aead_xchacha20_poly1305() },
        { CF_CIPHER("AES_128_GCM"), EVP_aead_aes_128_gcm() },
        { CF_CIPHER("AES_256_GCM"), EVP_aead_aes_256_gcm() },
#if defined(CRYPTOFUZZ_BORINGSSL)
        { CF_CIPHER("AES_256_CBC_HMAC_SHA256"), EVP_aead_aes_128_ctr_hmac_sha256() },
        { CF_CIPHER("AES_128_CTR_HMAC_SHA256"), EVP_aead_aes_128_ctr_hmac_sha256() },
        { CF_CIPHER("AES_256_CTR_HMAC_SHA256"), EVP_aead_aes_256_ctr_hmac_sha256() },
        { CF_CIPHER("AES_128_GCM_SIV"), EVP_aead_aes_128_gcm_siv() },
        { CF_CIPHER("AES_256_GCM_SIV"), EVP_aead_aes_256_gcm_siv() },
        { CF_CIPHER("AES_128_CCM_BLUETOOTH"), EVP_aead_aes_128_ccm_bluetooth() },
        { CF_CIPHER("AES_128_CCM_BLUETOOTH_8"), EVP_aead_aes_128_ccm_bluetooth_8() },
        { CF_CIPHER("AES_128_CBC_SHA1_TLS"), EVP_aead_aes_128_cbc_sha1_tls() },
        { CF_CIPHER("AES_128_CBC_SHA1_TLS_IMPLICIT_IV"), EVP_aead_aes_128_cbc_sha1_tls_implicit_iv() },
        { CF_CIPHER("AES_128_CBC_SHA256_TLS"), EVP_aead_aes_128_cbc_sha256_tls() },
        { CF_CIPHER("AES_256_CBC_SHA1_TLS"), EVP_aead_aes_256_cbc_sha1_tls() },
        { CF_CIPHER("AES_256_CBC_SHA1_TLS_IMPLICIT_IV"), EVP_aead_aes_256_cbc_sha1_tls_implicit_iv() },
        { CF_CIPHER("AES_256_CBC_SHA256_TLS"), EVP_aead_aes_256_cbc_sha256_tls() },
        { CF_CIPHER("AES_256_CBC_SHA384_TLS"), EVP_aead_aes_256_cbc_sha384_tls() },
        { CF_CIPHER("DES_EDE3_CBC_SHA1_TLS"), EVP_aead_des_ede3_cbc_sha1_tls() },
        { CF_CIPHER("DES_EDE3_CBC_SHA1_TLS_IMPLICIT_IV"), EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv() },
        { CF_CIPHER("NULL_SHA1_TLS"), EVP_aead_null_sha1_tls() },
        { CF_CIPHER("AES_128_GCM_TLS12"), EVP_aead_aes_128_gcm_tls12() },
        { CF_CIPHER("AES_256_GCM_TLS12"), EVP_aead_aes_256_gcm_tls12() },
        { CF_CIPHER("AES_128_GCM_TLS13"), EVP_aead_aes_128_gcm_tls13() },
        { CF_CIPHER("AES_256_GCM_TLS13"), EVP_aead_aes_256_gcm_tls13() },
#endif
    };

    if ( LUT.find(cipherType.Get()) == LUT.end() ) {
        return nullptr;
    }

    return LUT.at(cipherType.Get());
}
#endif

std::optional<component::Digest> OpenSSL::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    CF_EVP_MD_CTX ctx(ds);
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_EQ(EVP_DigestInit_ex(ctx.GetPtr(), md, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestUpdate(ctx.GetPtr(), part.first, part.second), 1);
    }

    /* Finalize */
    {
        unsigned int len = -1;
        unsigned char md[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(EVP_DigestFinal_ex(ctx.GetPtr(), md, &len), 1);

        ret = component::Digest(md, len);
    }

end:
    return ret;
}

#if !defined(CRYPTOFUZZ_BORINGSSL)
std::optional<component::MAC> OpenSSL::OpHMAC_EVP(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    CF_EVP_MD_CTX ctx(ds);
    const EVP_MD* md = nullptr;
    EVP_PKEY *pkey = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), nullptr);
        CF_CHECK_EQ(EVP_DigestSignInit(ctx.GetPtr(), nullptr, md, nullptr, pkey), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestSignUpdate(ctx.GetPtr(), part.first, part.second), 1);
    }

    /* Finalize */
    {
        size_t len = -1;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(EVP_DigestSignFinal(ctx.GetPtr(), out, &len), 1);

        ret = component::MAC(out, len);
    }

end:
    EVP_PKEY_free(pkey);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_OPENSSL_102)
std::optional<component::MAC> OpenSSL::OpHMAC_HMAC(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    CF_HMAC_CTX ctx(ds);
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        /* TODO remove ? */
        HMAC_CTX_reset(ctx.GetPtr());
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_EQ(HMAC_Init_ex(ctx.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), md, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(HMAC_Update(ctx.GetPtr(), part.first, part.second), 1);
    }

    /* Finalize */
    {
        unsigned int len = -1;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(HMAC_Final(ctx.GetPtr(), out, &len), 1);

        ret = component::MAC(out, len);
    }

end:
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
    (void)cipherType;
    (void)ctx;

    bool ret = false;

    const size_t ivLength = EVP_CIPHER_iv_length(cipher);
    if ( ivLength != inputIvLength ) {
#if defined(CRYPTOFUZZ_LIBRESSL) || defined(CRYPTOFUZZ_OPENSSL_102)
        if ( repository::IsCCM( cipherType ) ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, inputIvLength, nullptr), 1);
            ret = true;
        } else if ( repository::IsGCM( cipherType ) ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, inputIvLength, nullptr), 1);
            ret = true;
        }
#else
        if ( isAEAD(cipher) == true ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, inputIvLength, nullptr), 1);
            ret = true;
        }
#endif
    } else {
        return true;
    }

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

    std::optional<component::Ciphertext> ret = std::nullopt;

    /* No support for AEAD tags and AAD with BIO */
    if ( op.tagSize != std::nullopt || op.aad != std::nullopt ) {
        return ret;
    }

#if defined(CRYPTOFUZZ_OPENSSL_102)
    /* WRAP ciphers crash in OpenSSL 1.0.2 */
    if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
        return ret;
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
            printf("Error: BIO_read reports more written bytes than the buffer can hold\n");
            abort();
        }

        {
            /* Check if more data can be read. If yes, then the buffer is too small.
             * BIO_eof doesn't seem to work as expected here. */
            int num2;
            uint8_t out2[1];
            CF_CHECK_EQ(num2 = BIO_read(bio_cipher, out2, sizeof(out2)), 0);
        }

        /* Currently disabled to due length/padding mismatches with EVP, which are not necessarily OpenSSL's fault.
         * (needs researching)
         */
        //ret = component::Ciphertext(Buffer(out, num));
    }

end:
    BIO_free_all(bio_cipher);
    util::free(out);

    return ret;
}
#endif

std::optional<component::Ciphertext> OpenSSL::OpSymmetricEncrypt_EVP(operation::SymmetricEncrypt& op, Datasource& ds) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    util::Multipart partsCleartext, partsAAD;

    const EVP_CIPHER* cipher = nullptr;
    CF_EVP_CIPHER_CTX ctx(ds);

    size_t out_size = op.ciphertextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);
    uint8_t* outTag = op.tagSize != std::nullopt ? util::malloc(*op.tagSize) : nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);
        if ( op.tagSize != std::nullopt || op.aad != std::nullopt ) {
            /* Trying to treat non-AEAD with AEAD-specific features (tag, aad)
             * leads to all kinds of gnarly memory bugs in OpenSSL.
             * It is quite arguably misuse of the OpenSSL API, so don't do this.
             */
            CF_CHECK_EQ(isAEAD(cipher), true);

            /* Special TLS AEAD ciphers that should not be attempted to use with aad/tag */
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("RC4_HMAC_MD5"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_128_CBC_HMAC_SHA1"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_256_CBC_HMAC_SHA1"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_128_CBC_HMAC_SHA256"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_256_CBC_HMAC_SHA256"));
        }

        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), cipher, nullptr, nullptr, nullptr), 1);

        /* Must be a multiple of the block size of this cipher */
        //CF_CHECK_EQ(op.cleartext.GetSize() % EVP_CIPHER_block_size(cipher), 0);

        /* Convert cleartext to parts */
        partsCleartext = util::CipherInputTransform(ds, op.cipher.cipherType, out, out_size, op.cleartext.GetPtr(), op.cleartext.GetSize());
        partsCleartext = { { op.cleartext.GetPtr(), op.cleartext.GetSize()} };

        if ( op.aad != std::nullopt ) {
            if ( repository::IsCCM( op.cipher.cipherType.Get() ) ) {
                /* CCM does not support chunked AAD updating.
                 * See: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_CCM_mode
                 */
                partsAAD = { {op.aad->GetPtr(), op.aad->GetSize()} };
            } else {
                partsAAD = util::ToParts(ds, *(op.aad));
            }
        }

        CF_CHECK_EQ(checkSetIVLength(op.cipher.cipherType.Get(), cipher, ctx.GetPtr(), op.cipher.iv.GetSize()), true);
        CF_CHECK_EQ(checkSetKeyLength(cipher, ctx.GetPtr(), op.cipher.key.GetSize()), true);

        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr()), 1);

        /* Disable ECB padding for consistency with mbed TLS */
        if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_set_padding(ctx.GetPtr(), 0), 1);
        }
    }

    /* Process */
    {
        /* Set AAD */
        if ( op.aad != std::nullopt ) {
            /* If the cipher is CCM, the total cleartext size needs to be indicated explicitly
             * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
             */
            if ( repository::IsCCM(op.cipher.cipherType.Get()) == true ) {
                int len;
                CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), nullptr, &len, nullptr, op.cleartext.GetSize()), 1);
            }

            for (const auto& part : partsAAD) {
                int len;
                CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), nullptr, &len, part.first, part.second), 1);
            }
        }

        for (const auto& part : partsCleartext) {
            /* "the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1)" */
            CF_CHECK_GTE(out_size, part.second + EVP_CIPHER_block_size(cipher) - 1);

            int len = -1;
            CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), out + outIdx, &len, part.first, part.second), 1);
            outIdx += len;
            out_size -= len;
        }
    }

    /* Finalize */
    {
        CF_CHECK_GTE(out_size, static_cast<size_t>(EVP_CIPHER_block_size(cipher)));

        int len = -1;
        CF_CHECK_EQ(EVP_EncryptFinal_ex(ctx.GetPtr(), out + outIdx, &len), 1);
        outIdx += len;

        if ( op.tagSize != std::nullopt ) {
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
            /* Get tag.
             *
             * See comments around EVP_CTRL_AEAD_SET_TAG in OpSymmetricDecrypt_EVP for reasons
             * as to why this is disabled for LibreSSL.
             */
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx.GetPtr(), EVP_CTRL_AEAD_GET_TAG, *op.tagSize, outTag), 1);
            ret = component::Ciphertext(Buffer(out, outIdx), Buffer(outTag, *op.tagSize));
#endif
        } else {
            ret = component::Ciphertext(Buffer(out, outIdx));
        }
    }

end:

    util::free(out);
    util::free(outTag);

    return ret;
}

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
std::optional<component::Ciphertext> OpenSSL::AEAD_Encrypt(operation::SymmetricEncrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::Ciphertext> ret = std::nullopt;

    if ( op.tagSize == std::nullopt ) {
        return ret;
    }

    const EVP_AEAD* aead = nullptr;
    EVP_AEAD_CTX ctx;
    bool ctxInitialized = false;
    size_t len;

    size_t out_size = op.ciphertextSize;
    uint8_t* out = util::malloc(out_size);

    const size_t tagSize = op.tagSize != std::nullopt ? *op.tagSize : 0;

    /* Initialize */
    {
        CF_CHECK_NE(aead = toEVPAEAD(op.cipher.cipherType), nullptr);
        CF_CHECK_NE(EVP_AEAD_CTX_init(
                    &ctx,
                    aead,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    tagSize,
                    nullptr), 0);
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
                    op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                    op.aad != std::nullopt ? op.aad->GetSize() : 0),
                0);
    }

    /* Finalize */
    {
        /* The tag should be part of the output.
         * Hence, the total output size should be equal or greater than the tag size.
         * Note that removing this check will lead to an overflow below. */
        if ( tagSize > len ) {
            printf("tagSize > len in %s\n", __FUNCTION__);
            abort();
        }

        const size_t ciphertextSize = len - tagSize;

        ret = component::Ciphertext(Buffer(out, ciphertextSize), Buffer(out + ciphertextSize, tagSize));
    }

end:
    if ( ctxInitialized == true ) {
        EVP_AEAD_CTX_cleanup(&ctx);
    }

    util::free(out);

    return ret;
}
#endif

std::optional<component::Ciphertext> OpenSSL::AES_Encrypt(operation::SymmetricEncrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::Ciphertext> ret = std::nullopt;

    AES_KEY key;
    uint8_t* out = nullptr;

    /* Initialize */
    {
        CF_CHECK_EQ(op.aad, std::nullopt);
        CF_CHECK_EQ(op.tagSize, std::nullopt);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 0);
        CF_CHECK_GT(op.cleartext.GetSize(), 0);
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
        CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
        CF_CHECK_EQ(AES_set_encrypt_key(op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, &key), 0);
    }

    /* Process */
    {
#if 0
        bool useOverlap = false;
        uint64_t cleartextIndex;
        try {
            bool _useOverlap = ds.Get<bool>();
            if ( _useOverlap == true ) {
                cleartextIndex = ds.Get<uint64_t>() % op.cleartext.GetSize();
                useOverlap = true;
            }
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        if ( useOverlap == true ) {
            /* in and out are allowed to overlap */
            out = (uint8_t*)malloc(op.cleartext.GetSize() + cleartextIndex);
            memcpy(out + cleartextIndex, op.cleartext.GetPtr(), op.cleartext.GetSize());

            for (size_t i = 0; i < op.cleartext.GetSize(); i += 16) {
                AES_encrypt(out + cleartextIndex + i, out + i, &key);
            }
        } else
#endif
        {
            out = (uint8_t*)malloc(op.ciphertextSize);

            for (size_t i = 0; i < op.cleartext.GetSize(); i += 16) {
                AES_encrypt(op.cleartext.GetPtr() + i, out + i, &key);
            }
        }
    }

    /* Finalize */
    {
        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
    }

end:

    free(out);

    return ret;
}

std::optional<component::Ciphertext> OpenSSL::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.cipher.cipherType.Get() == CF_CIPHER("AES") ) {
        return AES_Encrypt(op, ds);
    }

#if defined(CRYPTOFUZZ_OPENSSL_110)
    if ( repository::IsCCM( op.cipher.cipherType.Get() ) ) {
        return std::nullopt;
    }
#endif

#if defined(CRYPTOFUZZ_OPENSSL_102) || defined(CRYPTOFUZZ_OPENSSL_110)
    /* Prevent OOB write for large keys in RC5.
     * Fixed in OpenSSL master, but will not be fixed for OpenSSL 1.0.2 and 1.1.0
     */
    if ( op.cipher.key.GetSize() > 255 ) {
        switch ( op.cipher.cipherType.Get() ) {
            case CF_CIPHER("RC5_32_12_16_ECB"):
            case CF_CIPHER("RC5_32_12_16_CFB"):
            case CF_CIPHER("RC5_32_12_16_OFB"):
            case CF_CIPHER("RC5_32_12_16_CBC"):
                return std::nullopt;
        }
    }
#endif

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
    if ( toEVPAEAD(op.cipher.cipherType) != nullptr ) {
        bool do_AEAD_Encrypt = true;
        if ( op.tagSize != std::nullopt ) {
            do_AEAD_Encrypt = false;
        } else if ( op.aad != std::nullopt ) {
            do_AEAD_Encrypt = false;
        }

#if defined(CRYPTOFUZZ_BORINGSSL)
        if ( do_AEAD_Encrypt == true ) {
            if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20_POLY1305") &&
                    op.cipher.cipherType.Get() != CF_CIPHER("XCHACHA20_POLY1305") ) {
                try {
                    do_AEAD_Encrypt = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            }
        }
#endif

        if ( do_AEAD_Encrypt == true ) {
            return AEAD_Encrypt(op, ds);
        } else {
            /* Fall through to OpSymmetricEncrypt_EVP/OpSymmetricEncrypt_BIO */
        }
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
std::optional<component::Cleartext> OpenSSL::OpSymmetricDecrypt_BIO(operation::SymmetricDecrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::Cleartext> ret = std::nullopt;

    /* No support for AEAD tags and AAD with BIO */
    if ( op.aad != std::nullopt || op.tag != std::nullopt ) {
        return ret;
    }

#if defined(CRYPTOFUZZ_OPENSSL_102)
    /* WRAP ciphers crash in OpenSSL 1.0.2 */
    if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
        return ret;
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
            printf("Error: BIO_read reports more written bytes than the buffer can hold\n");
            abort();
        }

        {
            /* Check if more data can be read. If yes, then the buffer is too small.
             * BIO_eof doesn't seem to work as expected here. */
            int num2;
            uint8_t out2[1];
            CF_CHECK_EQ(num2 = BIO_read(bio_cipher, out2, sizeof(out2)), 0);
        }

        /* Currently disabled to due length/padding mismatches with EVP, which are not necessarily OpenSSL's fault.
         * (needs researching)
         */
        //ret = component::Cleartext(out, num);
    }

end:
    BIO_free_all(bio_cipher);
    util::free(out);

    return ret;
}
#endif

std::optional<component::Cleartext> OpenSSL::OpSymmetricDecrypt_EVP(operation::SymmetricDecrypt& op, Datasource& ds) {
    std::optional<component::Cleartext> ret = std::nullopt;

    util::Multipart partsCiphertext, partsAAD;

    const EVP_CIPHER* cipher = nullptr;
    CF_EVP_CIPHER_CTX ctx(ds);

    size_t out_size = op.cleartextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);
        if ( op.tag != std::nullopt || op.aad != std::nullopt ) {
            /* Trying to treat non-AEAD with AEAD-specific features (tag, aad)
             * leads to all kinds of gnarly memory bugs in OpenSSL.
             * It is quite arguably misuse of the OpenSSL API, so don't do this.
             */
            CF_CHECK_EQ(isAEAD(cipher), true);

            /* Special TLS AEAD ciphers that should not be attempted to use with aad/tag */
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("RC4_HMAC_MD5"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_128_CBC_HMAC_SHA1"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_256_CBC_HMAC_SHA1"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_128_CBC_HMAC_SHA256"));
            CF_CHECK_NE(op.cipher.cipherType.Get(), CF_CIPHER("AES_256_CBC_HMAC_SHA256"));
        }
        CF_CHECK_EQ(EVP_DecryptInit_ex(ctx.GetPtr(), cipher, nullptr, nullptr, nullptr), 1);

        /* Must be a multiple of the block size of this cipher */
        //CF_CHECK_EQ(op.ciphertext.GetSize() % EVP_CIPHER_block_size(cipher), 0);

        /* Convert ciphertext to parts */
        partsCiphertext = util::CipherInputTransform(ds, op.cipher.cipherType, out, out_size, op.ciphertext.GetPtr(), op.ciphertext.GetSize());

        if ( op.aad != std::nullopt ) {
            if ( repository::IsCCM( op.cipher.cipherType.Get() ) ) {
                /* CCM does not support chunked AAD updating.
                 * See: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_CCM_mode
                 */
                partsAAD = { {op.aad->GetPtr(), op.aad->GetSize()} };
            } else {
                partsAAD = util::ToParts(ds, *(op.aad));
            }
        }

        CF_CHECK_EQ(checkSetIVLength(op.cipher.cipherType.Get(), cipher, ctx.GetPtr(), op.cipher.iv.GetSize()), true);
        CF_CHECK_EQ(checkSetKeyLength(cipher, ctx.GetPtr(), op.cipher.key.GetSize()), true);

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
        /* Set tag.
         *
         * LibreSSL supports setting the tag via the EVP interface with EVP_CTRL_GCM_SET_TAG for GCM,
         * and EVP_CTRL_CCM_SET_TAG for CCM, but does not provide a generic setter like EVP_CTRL_AEAD_SET_TAG
         * that also sets the tag for chacha20-poly1305.
         * At the moment, LibreSSL should never arrive here if tag is not nullopt; it is direct to AEAD_Decrypt
         * in that case.
         * Later, this can be changed to use the EVP interface for GCM and CCM ciphers.
         */
        if ( op.tag != std::nullopt ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx.GetPtr(), EVP_CTRL_AEAD_SET_TAG, op.tag->GetSize(), (void*)op.tag->GetPtr()), 1);
        }
#endif

        CF_CHECK_EQ(EVP_DecryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr()), 1);

        /* Disable ECB padding for consistency with mbed TLS */
        if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_set_padding(ctx.GetPtr(), 0), 1);
        }
    }

    /* Process */
    {
        /* Set AAD */
        if ( op.aad != std::nullopt ) {

            /* If the cipher is CCM, the total cleartext size needs to be indicated explicitly
             * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
             */
            if ( repository::IsCCM(op.cipher.cipherType.Get()) == true ) {
                int len;
                CF_CHECK_EQ(EVP_DecryptUpdate(ctx.GetPtr(), nullptr, &len, nullptr, op.ciphertext.GetSize()), 1);
            }

            for (const auto& part : partsAAD) {
                int len;
                CF_CHECK_EQ(EVP_DecryptUpdate(ctx.GetPtr(), nullptr, &len, part.first, part.second), 1);
            }
        }

        /* Set ciphertext */
        for (const auto& part : partsCiphertext) {
            CF_CHECK_GTE(out_size, part.second + EVP_CIPHER_block_size(cipher));

            int len = -1;
            CF_CHECK_EQ(EVP_DecryptUpdate(ctx.GetPtr(), out + outIdx, &len, part.first, part.second), 1);

            outIdx += len;
            out_size -= len;
        }
    }

    /* Finalize */
    {
        CF_CHECK_GTE(out_size, static_cast<size_t>(EVP_CIPHER_block_size(cipher)));

        int len = -1;
        CF_CHECK_EQ(EVP_DecryptFinal_ex(ctx.GetPtr(), out + outIdx, &len), 1);
        outIdx += len;

        ret = component::Cleartext(out, outIdx);
    }

end:

    util::free(out);

    return ret;
}

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
std::optional<component::Cleartext> OpenSSL::AEAD_Decrypt(operation::SymmetricDecrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::Cleartext> ret = std::nullopt;

    const EVP_AEAD* aead = nullptr;
    EVP_AEAD_CTX ctx;
    bool ctxInitialized = false;
    size_t len;

    size_t out_size = op.cleartextSize;
    uint8_t* out = util::malloc(out_size);

    const size_t tagSize = op.tag != std::nullopt ? op.tag->GetSize() : 0;

    /* Initialize */
    {
        CF_CHECK_NE(aead = toEVPAEAD(op.cipher.cipherType), nullptr);
        CF_CHECK_NE(EVP_AEAD_CTX_init(
                    &ctx,
                    aead,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    tagSize,
                    nullptr), 0);
        ctxInitialized = true;
    }

    /* Process */
    {
        /* OpenSSL and derivates consume the ciphertext + tag in concatenated form */
        std::vector<uint8_t> ciphertextAndTag(op.ciphertext.GetSize() + tagSize);
        memcpy(ciphertextAndTag.data(), op.ciphertext.GetPtr(), op.ciphertext.GetSize());
        if ( tagSize > 0 ) {
            memcpy(ciphertextAndTag.data() + op.ciphertext.GetSize(), op.tag->GetPtr(), tagSize);
        }

        CF_CHECK_NE(EVP_AEAD_CTX_open(&ctx,
                    out,
                    &len,
                    out_size,
                    op.cipher.iv.GetPtr(),
                    op.cipher.iv.GetSize(),
                    ciphertextAndTag.data(),
                    ciphertextAndTag.size(),
                    op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                    op.aad != std::nullopt ? op.aad->GetSize() : 0),
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

std::optional<component::Cleartext> OpenSSL::AES_Decrypt(operation::SymmetricDecrypt& op, Datasource& ds) {
    (void)ds;

    std::optional<component::Cleartext> ret = std::nullopt;

    AES_KEY key;
    uint8_t* out = nullptr;

    /* Initialize */
    {
        CF_CHECK_EQ(op.aad, std::nullopt);
        CF_CHECK_EQ(op.tag, std::nullopt);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 0);
        CF_CHECK_GT(op.ciphertext.GetSize(), 0);
        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
        CF_CHECK_EQ(AES_set_decrypt_key(op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, &key), 0);
    }

    /* Process */
    {
#if 0
        bool useOverlap = false;
        uint64_t ciphertextIndex;
        try {
            bool _useOverlap = ds.Get<bool>();
            if ( _useOverlap == true ) {
                ciphertextIndex = ds.Get<uint64_t>() % op.ciphertext.GetSize();
                useOverlap = true;
            }
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        if ( useOverlap == true ) {
            /* in and out are allowed to overlap */
            out = (uint8_t*)malloc(op.ciphertext.GetSize() + ciphertextIndex);
            memcpy(out + ciphertextIndex, op.ciphertext.GetPtr(), op.ciphertext.GetSize());

            for (size_t i = 0; i < op.ciphertext.GetSize(); i += 16) {
                AES_decrypt(out + ciphertextIndex + i, out + i, &key);
            }
        } else
#endif
        {
            out = (uint8_t*)malloc(op.cleartextSize);

            for (size_t i = 0; i < op.ciphertext.GetSize(); i += 16) {
                AES_decrypt(op.ciphertext.GetPtr() + i, out + i, &key);
            }
        }
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, op.ciphertext.GetSize());
    }

end:

    free(out);

    return ret;
}

std::optional<component::Cleartext> OpenSSL::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.cipher.cipherType.Get() == CF_CIPHER("AES") ) {
        return AES_Decrypt(op, ds);
    }

#if defined(CRYPTOFUZZ_OPENSSL_102) || defined(CRYPTOFUZZ_OPENSSL_110)
    /* Prevent OOB write for large keys in RC5.
     * Fixed in OpenSSL master, but will not be fixed for OpenSSL 1.0.2 and 1.1.0
     */
    if ( op.cipher.key.GetSize() > 255 ) {
        switch ( op.cipher.cipherType.Get() ) {
            case CF_CIPHER("RC5_32_12_16_ECB"):
            case CF_CIPHER("RC5_32_12_16_CFB"):
            case CF_CIPHER("RC5_32_12_16_OFB"):
            case CF_CIPHER("RC5_32_12_16_CBC"):
                return std::nullopt;
        }
    }
#endif

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
    if ( toEVPAEAD(op.cipher.cipherType) != nullptr ) {
        if ( op.tag != std::nullopt || op.aad != std::nullopt ) {
            /* See comment at OpSymmetricEncrypt */
            return AEAD_Decrypt(op, ds);
        }
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

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
std::optional<component::Key> OpenSSL::OpKDF_SCRYPT_EVP_PKEY(operation::KDF_SCRYPT& op) const {
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

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
std::optional<component::Key> OpenSSL::OpKDF_SCRYPT_EVP_KDF(operation::KDF_SCRYPT& op) const {
    std::optional<component::Key> ret = std::nullopt;
    EVP_KDF_CTX *kctx = nullptr;

    size_t out_size = op.keySize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(kctx = EVP_KDF_CTX_new_id(EVP_KDF_SCRYPT), nullptr);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_PASS, op.password.GetPtr(), op.password.GetSize()), 1);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SALT, op.salt.GetPtr(), op.salt.GetSize()), 1);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_N, op.N) , 1);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_R, op.r) , 1);
        CF_CHECK_EQ(EVP_KDF_ctrl(kctx, EVP_KDF_CTRL_SET_SCRYPT_P, op.p) , 1);
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

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
std::optional<component::Key> OpenSSL::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
 #if defined(CRYPTOFUZZ_BORINGSSL)
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Key> ret = std::nullopt;

    size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    size_t maxMem = 0;
    try {
        maxMem = ds.Get<uint64_t>() % (64*1024*1024);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    CF_CHECK_EQ(EVP_PBE_scrypt(
                (const char*)(op.password.GetPtr()),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.N,
                op.r,
                op.p,
                maxMem,
                out,
                outSize), 1);

    ret = component::Key(out, outSize);

end:
    util::free(out);

    return ret;
 #else
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useEVP_PKEY = true;
    try {
        useEVP_PKEY = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( useEVP_PKEY == true ) {
        return OpKDF_SCRYPT_EVP_PKEY(op);
    } else {
        return OpKDF_SCRYPT_EVP_KDF(op);
    }
 #endif
}
#endif

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
std::optional<component::Key> OpenSSL::OpKDF_HKDF(operation::KDF_HKDF& op) {
 #if defined(CRYPTOFUZZ_BORINGSSL)
    std::optional<component::Key> ret = std::nullopt;
    const EVP_MD* md = nullptr;

    const size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
    CF_CHECK_EQ(
            HKDF(out,
                outSize,
                md,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.info.GetPtr(),
                op.info.GetSize()), 1);

    ret = component::Key(out, outSize);

end:
    util::free(out);

    return ret;
 #else
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
        CF_CHECK_EQ(EVP_PKEY_CTX_set_hkdf_md(pctx, md), 1);
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
 #endif
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

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110)
std::optional<component::Key> OpenSSL::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
 #if defined(CRYPTOFUZZ_BORINGSSL)
    std::optional<component::Key> ret = std::nullopt;
    const EVP_MD* md = nullptr;

    const size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
    CF_CHECK_EQ(PKCS5_PBKDF2_HMAC(
                (const char*)(op.password.GetPtr()),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.iterations,
                md,
                outSize,
                out), 1);

    ret = component::Key(out, outSize);
end:
    util::free(out);

    return ret;
 #else
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
 #endif
}
#endif

std::optional<component::MAC> OpenSSL::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    CF_CMAC_CTX ctx(ds);
    const EVP_CIPHER* cipher = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(cipher = toEVPCIPHER(op.cipher.cipherType), nullptr);
        CF_CHECK_EQ(CMAC_Init(ctx.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), cipher, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(CMAC_Update(ctx.GetPtr(), part.first, part.second), 1);
    }

    /* Finalize */
    {
        size_t len = 0;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(CMAC_Final(ctx.GetPtr(), out, &len), 1);
        ret = component::MAC(out, len);
    }

end:
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
