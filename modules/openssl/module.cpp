#include "module.h"
#undef SHA1
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <openssl/aes.h>
#if defined(CRYPTOFUZZ_BORINGSSL)
#include <openssl/siphash.h>
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#endif
#include <openssl/rand.h>

#if defined(CRYPTOFUZZ_BORINGSSL)
#include <openssl/curve25519.h>
#elif defined(CRYPTOFUZZ_LIBRESSL)
extern "C" { void X25519_public_from_private(uint8_t out_public_value[32], const uint8_t private_key[32]); }
#else
/* OpenSSL */
extern "C" { void ossl_x25519_public_from_private(uint8_t out_public_value[32], const uint8_t private_key[32]); }
extern "C" { void ossl_x448_public_from_private(uint8_t out_public_value[56], const uint8_t private_key[56]); }
#define X25519_public_from_private ossl_x25519_public_from_private
#define X448_public_from_private ossl_x448_public_from_private
#endif

#include "module_internal.h"
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

fuzzing::datasource::Datasource* global_ds = nullptr;

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
const RAND_METHOD* cryptofuzz_openssl_rand_default_method;

static int cryptofuzz_openssl_default_rand_bytes(unsigned char *buf, int num) {
    CF_ASSERT(cryptofuzz_openssl_rand_default_method != nullptr, "default rand method is NULL");

    return cryptofuzz_openssl_rand_default_method->bytes(buf, num);
}

static int cryptofuzz_openssl_rand_bytes(unsigned char *buf, int num)
{
    CF_ASSERT(num >= 0, "called rand_bytes with num < 0");

    if ( num == 0 ) {
        return 1;
    }

    if ( global_ds == nullptr ) {
        return cryptofuzz_openssl_default_rand_bytes(buf, num);
    }

    try {
        if ( global_ds->Get<bool>() == false ) {
            return cryptofuzz_openssl_default_rand_bytes(buf, num);
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
        return cryptofuzz_openssl_default_rand_bytes(buf, num);
    }

    try {
        const auto data = global_ds->GetData(0, num, num);
        memcpy(buf, data.data(), num);
        return 1;
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
        return 0;
    }
}

static int cryptofuzz_openssl_rand_status(void)
{
    return 1;
}

static RAND_METHOD cryptofuzz_openssl_rand_method = {
    nullptr,
    cryptofuzz_openssl_rand_bytes,
    nullptr,
    nullptr,
    cryptofuzz_openssl_rand_bytes,
    cryptofuzz_openssl_rand_status
};
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
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

OpenSSL::OpenSSL(void) :
    Module("OpenSSL") {
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
    CF_ASSERT(
            CRYPTO_set_mem_functions(
                OPENSSL_custom_malloc,
                OPENSSL_custom_realloc,
                OPENSSL_custom_free) == 1,
    "Cannot set memory functions");
#endif

#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
     OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#else
     OpenSSL_add_all_algorithms();
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
     CF_ASSERT((cryptofuzz_openssl_rand_default_method = RAND_get_rand_method()) != nullptr,
         "Cannot retrieve default rand method");
     CF_ASSERT(RAND_set_rand_method(&cryptofuzz_openssl_rand_method) == 1,
         "Cannot set default rand method");
#endif
}


bool OpenSSL::isAEAD(const EVP_CIPHER* ctx, const uint64_t cipherType) const {
#if defined(CRYPTOFUZZ_OPENSSL_098)
    (void)ctx;
    (void)cipherType;
    return false;
#else
    bool ret = false;

    /* Special TLS AEAD ciphers that should not be attempted to use with aad/tag or
     * non-default iv/key sizes */
    CF_CHECK_NE(cipherType, CF_CIPHER("RC4_HMAC_MD5"));
    CF_CHECK_NE(cipherType, CF_CIPHER("AES_128_CBC_HMAC_SHA1"));
    CF_CHECK_NE(cipherType, CF_CIPHER("AES_256_CBC_HMAC_SHA1"));
    CF_CHECK_NE(cipherType, CF_CIPHER("AES_128_CBC_HMAC_SHA256"));
    CF_CHECK_NE(cipherType, CF_CIPHER("AES_256_CBC_HMAC_SHA256"));

    ret = EVP_CIPHER_flags(ctx) & EVP_CIPH_FLAG_AEAD_CIPHER;

end:
    return ret;
#endif
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
        { CF_DIGEST("SHA512-256"), EVP_sha512_256() },
        { CF_DIGEST("BLAKE2B256"), EVP_blake2b256() },
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
        { CF_DIGEST("SHA3-224"), EVP_sha3_224() },
        { CF_DIGEST("SHA3-256"), EVP_sha3_256() },
        { CF_DIGEST("SHA3-384"), EVP_sha3_384() },
        { CF_DIGEST("SHA3-512"), EVP_sha3_512() },
        { CF_DIGEST("SHA512-224"), EVP_sha512_224() },
        { CF_DIGEST("SHA512-256"), EVP_sha512_256() },
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
#elif defined(CRYPTOFUZZ_OPENSSL_098)
        { CF_DIGEST("SHA1"), EVP_sha1() },
        { CF_DIGEST("SHA224"), EVP_sha224() },
        { CF_DIGEST("SHA256"), EVP_sha256() },
        { CF_DIGEST("SHA384"), EVP_sha384() },
        { CF_DIGEST("SHA512"), EVP_sha512() },
        { CF_DIGEST("MD2"), EVP_md2() },
        { CF_DIGEST("MD4"), EVP_md4() },
        { CF_DIGEST("MD5"), EVP_md5() },
        { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
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
#if defined(CRYPTOFUZZ_AWSLC)
        case CF_CIPHER("AES_256_XTS"):
            return EVP_aes_256_xts();
#endif
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
        case CF_CIPHER("DESX_A_CBC"):
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
        case CF_CIPHER("CHACHA20_POLY1305"):
            return EVP_chacha20_poly1305();
#elif defined(CRYPTOFUZZ_OPENSSL_098)
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
        case CF_CIPHER("DESX_A_CBC"):
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
        case CF_CIPHER("IDEA_ECB"):
            return EVP_idea_ecb();
        case CF_CIPHER("IDEA_CFB"):
            return EVP_idea_cfb();
        case CF_CIPHER("IDEA_OFB"):
            return EVP_idea_ofb();
        case CF_CIPHER("IDEA_CBC"):
            return EVP_idea_cbc();
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
        case CF_CIPHER("DESX_A_CBC"):
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
        case CF_CIPHER("DESX_A_CBC"):
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
        case CF_CIPHER("DESX_A_CBC"):
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

        /*  Disabled due to unfixed memory issues with wrap ciphers:
            https://github.com/openssl/openssl/issues/15728
            https://github.com/openssl/openssl/issues/12073
            https://github.com/openssl/openssl/issues/12014
        */
        //case CF_CIPHER("DES_EDE3_WRAP"):
        //    return EVP_des_ede3_wrap();
        //case CF_CIPHER("AES_128_WRAP"):
        //    return EVP_aes_128_wrap();
        //case CF_CIPHER("AES_128_WRAP_PAD"):
        //    return EVP_aes_128_wrap_pad();
        //case CF_CIPHER("AES_192_WRAP"):
        //    return EVP_aes_192_wrap();
        //case CF_CIPHER("AES_192_WRAP_PAD"):
        //    return EVP_aes_192_wrap_pad();
        //case CF_CIPHER("AES_256_WRAP"):
        //    return EVP_aes_256_wrap();
        //case CF_CIPHER("AES_256_WRAP_PAD"):
        //    return EVP_aes_256_wrap_pad();
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
        { CF_CIPHER("AES_256_CBC_SHA1_TLS"), EVP_aead_aes_256_cbc_sha1_tls() },
        { CF_CIPHER("AES_256_CBC_SHA1_TLS_IMPLICIT_IV"), EVP_aead_aes_256_cbc_sha1_tls_implicit_iv() },
        { CF_CIPHER("DES_EDE3_CBC_SHA1_TLS"), EVP_aead_des_ede3_cbc_sha1_tls() },
        { CF_CIPHER("DES_EDE3_CBC_SHA1_TLS_IMPLICIT_IV"), EVP_aead_des_ede3_cbc_sha1_tls_implicit_iv() },
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

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_OPENSSL_098)
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

#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
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

namespace OpenSSL_detail {
    std::optional<component::MAC> SipHash(operation::HMAC& op) {
        std::optional<component::MAC> ret = std::nullopt;
#if defined(CRYPTOFUZZ_BORINGSSL)
        if ( op.digestType.Get() != CF_DIGEST("SIPHASH64") ) {
            return ret;
        }
        if ( op.cipher.key.GetSize() != 16 ) {
            return ret;
        }

        uint64_t key[2];
        memcpy(&key[0], op.cipher.key.GetPtr(), 8);
        memcpy(&key[1], op.cipher.key.GetPtr() + 8, 8);

        const auto ret_uint64_t = SIPHASH_24(key, op.cleartext.GetPtr(), op.cleartext.GetSize());

        uint8_t ret_uint8_t[8];
        static_assert(sizeof(ret_uint8_t) == sizeof(ret_uint64_t));

        memcpy(ret_uint8_t, &ret_uint64_t, sizeof(ret_uint8_t));

        ret = component::MAC(ret_uint8_t, sizeof(ret_uint8_t));

        return ret;
#elif defined(CRYPTOFUZZ_LIBRESSL) || defined(CRYPTOFUZZ_OPENSSL_102) || defined(CRYPTOFUZZ_OPENSSL_098)
        (void)op;
#else
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        size_t macSize;
        util::Multipart parts;
        uint8_t* out = nullptr;

        EVP_MAC* siphash = nullptr;
        EVP_MAC_CTX *ctx = nullptr;
        OSSL_PARAM params[3], *p = params;

        /* Initialize */
        {
            macSize = op.digestType.Get() == CF_DIGEST("SIPHASH64") ? 8 : 16;
            parts = util::ToParts(ds, op.cleartext);
            siphash = EVP_MAC_fetch(nullptr, "SIPHASH", nullptr);
            ctx = EVP_MAC_CTX_new(siphash);

            unsigned int macSize_ui = macSize;
            *p++ = OSSL_PARAM_construct_uint(OSSL_MAC_PARAM_SIZE, &macSize_ui);

            *p = OSSL_PARAM_construct_end();

            CF_CHECK_EQ(EVP_MAC_init(ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize(), params), 1);

            out = util::malloc(macSize);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(EVP_MAC_update(ctx, part.first, part.second), 1);
        }

        /* Finalize */
        CF_CHECK_EQ(EVP_MAC_final(ctx, out, &macSize, macSize), 1);
        ret = component::MAC(out, macSize);
end:
        util::free(out);

        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(siphash);

#endif
        return ret;
    }
}

#if !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::MAC> OpenSSL::OpHMAC(operation::HMAC& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if (    op.digestType.Get() == CF_DIGEST("SIPHASH64") ||
            op.digestType.Get() == CF_DIGEST("SIPHASH128") ) {
        /* Not HMAC but invoking SipHash here anyway due to convenience. */
        return OpenSSL_detail::SipHash(op);
    }

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
    }

    if ( useEVP == true ) {
#if !defined(CRYPTOFUZZ_BORINGSSL)
        return OpHMAC_EVP(op, ds);
#else
        return OpHMAC_HMAC(op, ds);
#endif
    } else {
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        return OpHMAC_HMAC(op, ds);
#else
        return OpHMAC_EVP(op, ds);
#endif
    }
}
#endif

bool OpenSSL::checkSetIVLength(const uint64_t cipherType, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputIvLength) const {
    bool ret = false;

    const size_t ivLength = EVP_CIPHER_iv_length(cipher);
    const bool ivLengthMismatch = ivLength != inputIvLength;

    if ( isAEAD(cipher, cipherType) == false ) {
        /* Return true (success) if input IV length is expected IV length */
        return !ivLengthMismatch;
    }

    const bool isCCM = repository::IsCCM( cipherType );
#if defined(CRYPTOFUZZ_LIBRESSL) || defined(CRYPTOFUZZ_OPENSSL_102)
    const bool isGCM = repository::IsGCM( cipherType );
#endif

    /* Only AEAD ciphers past this point */

    /* EVP_CIPHER_iv_length may return the wrong default IV length for CCM ciphers.
     * Eg. EVP_CIPHER_iv_length returns 12 for EVP_aes_128_ccm() even though the
     * IV length is actually.
     *
     * Hence, with CCM ciphers set the desired IV length always.
     */

    if ( isCCM || ivLengthMismatch ) {
#if defined(CRYPTOFUZZ_OPENSSL_098)
        (void)ctx;
        goto end;
#elif defined(CRYPTOFUZZ_LIBRESSL) || defined(CRYPTOFUZZ_OPENSSL_102)
        if ( isCCM == true ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, inputIvLength, nullptr), 1);
        } else if ( isGCM == true ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, inputIvLength, nullptr), 1);
        } else {
            return false;
        }
#else
        CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, inputIvLength, nullptr), 1);
#endif
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
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        /* In OpenSSL 1.0.2 and 0.9.8, BIO_set_cipher does not return a value */
        CF_CHECK_EQ(
#endif
                BIO_set_cipher(bio_cipher, cipher, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), 1 /* encrypt */)
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        , 1)
#endif
           ;
    }

    /* Process */
    {
#if defined(CRYPTOFUZZ_OPENSSL_098)
        BIO_push(bio_cipher, BIO_new_mem_buf((void*)op.cleartext.GetPtr(), op.cleartext.GetSize()));
#else
        BIO_push(bio_cipher, BIO_new_mem_buf(op.cleartext.GetPtr(), op.cleartext.GetSize()));
#endif
        //CF_CHECK_EQ(BIO_write(bio_out, op.cleartext.GetPtr(), op.cleartext.GetSize()), static_cast<int>(op.cleartext.GetSize()));
    }

    /* Finalize */
    {
        int num;
        CF_CHECK_GTE(num = BIO_read(bio_cipher, out, op.ciphertextSize), 0);

        CF_ASSERT(
                num <= (int)op.ciphertextSize,
                "BIO_read reports more written bytes than the buffer can hold");

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
            CF_CHECK_EQ(isAEAD(cipher, op.cipher.cipherType.Get()), true);
        }

        if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
#if defined(CRYPTOFUZZ_OPENSSL_098)
            goto end;
#else
            /* noret */ EVP_CIPHER_CTX_set_flags(ctx.GetPtr(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
#endif
        }
        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), cipher, nullptr, nullptr, nullptr), 1);

        if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
            partsCleartext = util::Multipart{ {op.cleartext.GetPtr(), op.cleartext.GetSize()} };
        } else {
            /* Convert cleartext to parts */
            partsCleartext = util::CipherInputTransform(ds, op.cipher.cipherType, out, out_size, op.cleartext.GetPtr(), op.cleartext.GetSize());
        }

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

        if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20") ) {
            CF_CHECK_EQ(checkSetIVLength(op.cipher.cipherType.Get(), cipher, ctx.GetPtr(), op.cipher.iv.GetSize()), true);
        } else {
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);
        }
        CF_CHECK_EQ(checkSetKeyLength(cipher, ctx.GetPtr(), op.cipher.key.GetSize()), true);

        if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20") ) {
            CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr()), 1);
        } else {
            /* Prepend the 32 bit counter (which is 0) to the iv */
            uint8_t cc20IV[16];
            memset(cc20IV, 0, 4);
            memcpy(cc20IV + 4, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
            CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), cc20IV), 1);
        }

        /* Disable ECB padding for consistency with mbed TLS */
        if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_set_padding(ctx.GetPtr(), 0), 1);
        }
    }

    /* Process */
    {
        /* If the cipher is CCM, the total cleartext size needs to be indicated explicitly
         * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
         */
        if ( repository::IsCCM(op.cipher.cipherType.Get()) == true ) {
            int len;
            CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), nullptr, &len, nullptr, op.cleartext.GetSize()), 1);
        }

        /* Set AAD */
        if ( op.aad != std::nullopt ) {

            for (const auto& part : partsAAD) {
                int len;
                CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), nullptr, &len, part.first, part.second), 1);
            }
        }

        for (const auto& part : partsCleartext) {
            if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
                /* WRAP ciphers don't honor the default rule */
                CF_CHECK_GTE(out_size, part.second + EVP_CIPHER_block_size(cipher));
            } else {
                /* "the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1)" */
                CF_CHECK_GTE(out_size, part.second + EVP_CIPHER_block_size(cipher) - 1);
            }

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
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
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

    const EVP_AEAD* aead = nullptr;
    EVP_AEAD_CTX* ctx = nullptr;
    size_t len;

    size_t out_size = op.ciphertextSize;
    uint8_t* out = util::malloc(out_size);

    const size_t tagSize = op.tagSize != std::nullopt ? *op.tagSize : 0;

    /* Initialize */
    {
        CF_CHECK_NE(aead = toEVPAEAD(op.cipher.cipherType), nullptr);
#if defined(CRYPTOFUZZ_LIBRESSL)
		CF_CHECK_NE(ctx = EVP_AEAD_CTX_new(), nullptr);
        CF_CHECK_NE(EVP_AEAD_CTX_init(
                    ctx,
                    aead,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    tagSize,
                    nullptr), 0);
#else /* CRYPTOFUZZ_BORINGSSL */
        CF_CHECK_NE(ctx = EVP_AEAD_CTX_new(
                    aead,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    tagSize), nullptr);
#endif
    }

    /* Process */
    {
        CF_CHECK_NE(EVP_AEAD_CTX_seal(ctx,
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
        size_t tagSize2 = tagSize;
#if defined(CRYPTOFUZZ_BORINGSSL)
        if ( tagSize == 0 ) {
            CF_CHECK_EQ(EVP_AEAD_CTX_tag_len(ctx, &tagSize2, op.cleartext.GetSize(), 0), 1);
        }
#elif defined(CRYPTOFUZZ_LIBRESSL)
        /* LibreSSL does not have EVP_AEAD_CTX_tag_len */
        CF_CHECK_NE(tagSize, 0);
#endif

        /* The tag should be part of the output.
         * Hence, the total output size should be equal or greater than the tag size.
         * Note that removing this check will lead to an overflow below. */
        CF_ASSERT(op.cleartext.GetSize() + tagSize2 == len, "input + tag size != output length");

        if ( tagSize != 0 ) {
            const size_t ciphertextSize = len - tagSize2;
            ret = component::Ciphertext(Buffer(out, ciphertextSize), Buffer(out + ciphertextSize, tagSize));
        } else {
            /* Do not set ret if tag size is 0; the AEAD API cannot decrypt inputs whose tag size is 0,
             * because it interprets a tag size of 0 as the default tag size
             */
        }
    }

end:
    CF_NORET(EVP_AEAD_CTX_free(ctx));

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
        } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
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
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
    }

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
    if ( toEVPAEAD(op.cipher.cipherType) != nullptr ) {
        try {
            if ( ds.Get<bool>() == true ) {
                return AEAD_Encrypt(op, ds);
            }

            /* Fall through to OpSymmetricEncrypt_EVP/OpSymmetricEncrypt_BIO */

        } catch ( fuzzing::datasource::Datasource::OutOfData& ) { }
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
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        /* In OpenSSL 1.0.2, BIO_set_cipher does not return a value */
        CF_CHECK_EQ(
#endif
                BIO_set_cipher(bio_cipher, cipher, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), 0 /* decrypt */)
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
        , 1)
#endif
           ;
    }

    /* Process */
    {
#if defined(CRYPTOFUZZ_OPENSSL_098)
        BIO_push(bio_cipher, BIO_new_mem_buf((void*)op.ciphertext.GetPtr(), op.ciphertext.GetSize()));
#else
        BIO_push(bio_cipher, BIO_new_mem_buf(op.ciphertext.GetPtr(), op.ciphertext.GetSize()));
#endif
        //CF_CHECK_EQ(BIO_write(bio_out, op.cleartext.GetPtr(), op.cleartext.GetSize()), static_cast<int>(op.cleartext.GetSize()));
    }

    /* Finalize */
    {
        int num;
        CF_CHECK_GTE(num = BIO_read(bio_cipher, out, op.cleartextSize), 0);

        CF_ASSERT(
                num <= (int)op.cleartextSize,
                "BIO_read reports more written bytes than the buffer can hold");

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
            CF_CHECK_EQ(isAEAD(cipher, op.cipher.cipherType.Get()), true);
        }

        if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
#if defined(CRYPTOFUZZ_OPENSSL_098)
            goto end;
#else
            /* noret */ EVP_CIPHER_CTX_set_flags(ctx.GetPtr(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
#endif
        }

        CF_CHECK_EQ(EVP_DecryptInit_ex(ctx.GetPtr(), cipher, nullptr, nullptr, nullptr), 1);

        if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
            partsCiphertext = util::Multipart{ {op.ciphertext.GetPtr(), op.ciphertext.GetSize()} };
        } else {
            /* Convert ciphertext to parts */
            partsCiphertext = util::CipherInputTransform(ds, op.cipher.cipherType, out, out_size, op.ciphertext.GetPtr(), op.ciphertext.GetSize());
        }

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

        if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20") ) {
            CF_CHECK_EQ(checkSetIVLength(op.cipher.cipherType.Get(), cipher, ctx.GetPtr(), op.cipher.iv.GetSize()), true);
        } else {
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);
        }
        CF_CHECK_EQ(checkSetKeyLength(cipher, ctx.GetPtr(), op.cipher.key.GetSize()), true);

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
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
        if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20") ) {
            CF_CHECK_EQ(EVP_DecryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr()), 1);
        } else {
            /* Prepend the 32 bit counter (which is 0) to the iv */
            uint8_t cc20IV[16];
            memset(cc20IV, 0, 4);
            memcpy(cc20IV + 4, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
            CF_CHECK_EQ(EVP_DecryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), cc20IV), 1);
        }

        /* Disable ECB padding for consistency with mbed TLS */
        if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_set_padding(ctx.GetPtr(), 0), 1);
        }
    }

    /* Process */
    {
        /* If the cipher is CCM, the total cleartext size needs to be indicated explicitly
         * https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
         */
        if ( repository::IsCCM(op.cipher.cipherType.Get()) == true ) {
            int len;
            CF_CHECK_EQ(EVP_DecryptUpdate(ctx.GetPtr(), nullptr, &len, nullptr, op.ciphertext.GetSize()), 1);
        }

        /* Set AAD */
        if ( op.aad != std::nullopt ) {
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
    EVP_AEAD_CTX* ctx = nullptr;
    size_t len;

    size_t out_size = op.cleartextSize;
    uint8_t* out = util::malloc(out_size);

    const size_t tagSize = op.tag != std::nullopt ? op.tag->GetSize() : 0;

    /* Initialize */
    {
        CF_CHECK_NE(aead = toEVPAEAD(op.cipher.cipherType), nullptr);
#if defined(CRYPTOFUZZ_LIBRESSL)
		CF_CHECK_NE(ctx = EVP_AEAD_CTX_new(), nullptr);
        CF_CHECK_NE(EVP_AEAD_CTX_init(
                    ctx,
                    aead,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    tagSize,
                    nullptr), 0);
#else /* CRYPTOFUZZ_BORINGSSL */
        CF_CHECK_NE(ctx = EVP_AEAD_CTX_new(
                    aead,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    tagSize), nullptr);
#endif
    }

    /* Process */
    {
        /* OpenSSL and derivates consume the ciphertext + tag in concatenated form */
        std::vector<uint8_t> ciphertextAndTag(op.ciphertext.GetSize() + tagSize);
        memcpy(ciphertextAndTag.data(), op.ciphertext.GetPtr(), op.ciphertext.GetSize());
        if ( tagSize > 0 ) {
            memcpy(ciphertextAndTag.data() + op.ciphertext.GetSize(), op.tag->GetPtr(), tagSize);
        }

        CF_CHECK_NE(EVP_AEAD_CTX_open(ctx,
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
    CF_NORET(EVP_AEAD_CTX_free(ctx));

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
        } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
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
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
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

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::Key> OpenSSL::OpKDF_SCRYPT_EVP_PKEY(operation::KDF_SCRYPT& op) const {
    std::optional<component::Key> ret = std::nullopt;
    EVP_PKEY_CTX* pctx = nullptr;

    size_t out_size = op.keySize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_SCRYPT, nullptr), nullptr);
        CF_CHECK_EQ(EVP_PKEY_derive_init(pctx), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set1_pbe_pass(pctx, (const char*)op.password.GetPtr(), op.password.GetSize()), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set1_scrypt_salt(pctx, op.salt.GetPtr(), op.salt.GetSize()), 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_scrypt_N(pctx, op.N) , 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_scrypt_r(pctx, op.r) , 1);
        CF_CHECK_EQ(EVP_PKEY_CTX_set_scrypt_p(pctx, op.p) , 1);
    }

    /* Process/finalize */
    {
        CF_CHECK_EQ(EVP_PKEY_derive(pctx, out, &out_size) , 1);

        CF_CHECK_NE(out, nullptr);

        ret = component::Key(out, out_size);
    }

end:
    EVP_PKEY_CTX_free(pctx);
    util::free(out);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::Key> OpenSSL::OpKDF_SCRYPT_EVP_KDF(operation::KDF_SCRYPT& op) const {
    std::optional<component::Key> ret = std::nullopt;
    EVP_KDF_CTX* kctx = nullptr;
    OSSL_PARAM params[7], *p = params;
    uint8_t* out = util::malloc(op.keySize);

    {

        auto passwordCopy = op.password.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD,
                passwordCopy.data(),
                passwordCopy.size());

        auto saltCopy = op.salt.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT,
                saltCopy.data(),
                saltCopy.size());

        unsigned int N = op.N;
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_N, &N);

        unsigned int r = op.r;
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_R, &r);

        unsigned int p_ = op.p;
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_P, &p_);

        unsigned int maxmem = 1024;
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_SCRYPT_MAXMEM, &maxmem);

        *p = OSSL_PARAM_construct_end();

        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, OSSL_KDF_NAME_SCRYPT, nullptr);
            CF_CHECK_NE(kdf, nullptr);
            kctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            CF_CHECK_NE(kctx, nullptr);
        }

        CF_CHECK_GT(EVP_KDF_derive(kctx, out, op.keySize, params), 0);
    }

    /* Finalize */
    {
        ret = component::Key(out, op.keySize);
    }

end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);
    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::Key> OpenSSL::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
 #if defined(CRYPTOFUZZ_BORINGSSL)
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Key> ret = std::nullopt;

    size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    size_t maxMem = 0;
    try {
        maxMem = ds.Get<uint64_t>() % (64*1024*1024);
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
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
    } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
    }

    if ( useEVP_PKEY == true ) {
        return OpKDF_SCRYPT_EVP_PKEY(op);
    } else {
        return OpKDF_SCRYPT_EVP_KDF(op);
    }
 #endif
}
#endif

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
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

        CF_CHECK_NE(out, nullptr);

        ret = component::Key(out, out_size);
    }

end:
    EVP_PKEY_CTX_free(pctx);

    util::free(out);

    return ret;
 #endif
}
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
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

        /* Documentation:
         *
         * "If key is NULL then the maximum size of the output buffer is written to the keylen parameter."
         *
         * So in this case 'out_size' should not be interpreted as containing the output size,
         * and we shouldn't attempt to construct a result from it.
         */
        CF_CHECK_NE(out, nullptr);

        ret = component::Key(out, out_size);
    }

end:
    EVP_PKEY_CTX_free(pctx);

    util::free(out);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::Key> OpenSSL::OpKDF_PBKDF(operation::KDF_PBKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_KDF_CTX* kctx = nullptr;
    const EVP_MD* md = nullptr;
    OSSL_PARAM params[7], *p = params;
    uint8_t* out = util::malloc(op.keySize);

    {
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);

        auto passwordCopy = op.password.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD,
                passwordCopy.data(),
                passwordCopy.size());

        auto saltCopy = op.salt.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT,
                saltCopy.data(),
                saltCopy.size());

        unsigned int iterations = op.iterations;
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);

        unsigned int id = 1;
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_PKCS12_ID, &id);

        std::string mdName(EVP_MD_name(md));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdName.data(), mdName.size() + 1);

        int pkcs5 = 0;
        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);

        *p = OSSL_PARAM_construct_end();

        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "PKCS12KDF", nullptr);
            CF_CHECK_NE(kdf, nullptr);
            kctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            CF_CHECK_NE(kctx, nullptr);
        }

        CF_CHECK_GT(EVP_KDF_derive(kctx, out, op.keySize, params), 0);
    }

    /* Finalize */
    {
        ret = component::Key(out, op.keySize);
    }
end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
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
    EVP_KDF_CTX* kctx = nullptr;
    const EVP_MD* md = nullptr;
    OSSL_PARAM params[6], *p = params;
    uint8_t* out = util::malloc(op.keySize);

    {
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);

        auto passwordCopy = op.password.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD,
                passwordCopy.data(),
                passwordCopy.size());

        auto saltCopy = op.salt.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT,
                saltCopy.data(),
                saltCopy.size());

        unsigned int iterations = op.iterations;
        *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);

        std::string mdName(EVP_MD_name(md));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdName.data(), mdName.size() + 1);

        int pkcs5 = 0;
        *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &pkcs5);

        *p = OSSL_PARAM_construct_end();

        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, OSSL_KDF_NAME_PBKDF2, nullptr);
            CF_CHECK_NE(kdf, nullptr);
            kctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            CF_CHECK_NE(kctx, nullptr);
        }

        CF_CHECK_GT(EVP_KDF_derive(kctx, out, op.keySize, params), 0);
    }

    /* Finalize */
    {
        ret = component::Key(out, op.keySize);
    }

end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);

    return ret;
 #endif
}
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110)
std::optional<component::Key> OpenSSL::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    (void)op;
    std::optional<component::Key> ret = std::nullopt;

    /* Pending https://github.com/openssl/openssl/pull/12256 */
#if 0
    uint8_t* out = util::malloc(op.keySize);
    EVP_KDF_CTX *kctx = nullptr;
    OSSL_PARAM params[7], *p = params;

    /* Initialize */
    {
        const char* type = nullptr;
        switch ( op.type ) {
            case    0:
                type = SN_argon2d;
                break;
            case    1:
                type = SN_argon2i;
                break;
            case    2:
                type = SN_argon2id;
                break;
            default:
                goto end;
        }

        CF_CHECK_GTE(op.keySize, 64);
        CF_CHECK_EQ(op.threads, 1);

        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, type, nullptr);
            CF_CHECK_NE(kdf, nullptr);
            kctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            CF_CHECK_NE(kctx, nullptr);
        }

        {
            int threads = 1;
            int m_cost = op.memory;
            unsigned int iterations = op.iterations;

            auto passwordCopy = op.password.Get();
            p[0] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, passwordCopy.data(), passwordCopy.size());

            auto saltCopy = op.salt.Get();
            p[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, saltCopy.data(), saltCopy.size());

            p[2] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ARGON2_LANES, &threads);
            p[3] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_THREADS, &threads);
            p[4] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ARGON2_MEMCOST, &m_cost);
            p[5] = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
            p[6] = OSSL_PARAM_construct_end();
            CF_CHECK_EQ(EVP_KDF_CTX_set_params(kctx, params), 1);
        }
    }
    /* Process/finalize */
    {
        CF_CHECK_EQ(EVP_KDF_derive(kctx, out, op.keySize), 1);

        ret = component::Key(out, op.keySize);
    }

end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);
#endif

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_111) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::Key> OpenSSL::OpKDF_SSH(operation::KDF_SSH& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_KDF_CTX* kctx = nullptr;
    const EVP_MD* md = nullptr;
    OSSL_PARAM params[6], *p = params;
    uint8_t* out = util::malloc(op.keySize);

    {
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_EQ(op.type.GetSize(), 1);

        std::string mdName(EVP_MD_name(md));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdName.data(), mdName.size() + 1);

        auto keyCopy = op.key.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD,
                keyCopy.data(),
                keyCopy.size());

        auto xcghashCopy = op.xcghash.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SSHKDF_XCGHASH,
                xcghashCopy.data(),
                xcghashCopy.size());

        auto session_idCopy = op.session_id.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
                session_idCopy.data(),
                session_idCopy.size());


        /* Must be null-terminated even if size is specified.
         *
         * See also https://github.com/openssl/openssl/issues/14027
         */
        char type[2];
        type[0] = *(op.type.GetPtr());
        type[1] = 0;

        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
                type, sizeof(type));

        *p = OSSL_PARAM_construct_end();

        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, OSSL_KDF_NAME_SSHKDF, nullptr);
            CF_CHECK_NE(kdf, nullptr);
            kctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            CF_CHECK_NE(kctx, nullptr);
        }

        CF_CHECK_GT(EVP_KDF_derive(kctx, out, op.keySize, params), 0);
    }

    /* Finalize */
    {
        ret = component::Key(out, op.keySize);
    }

end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);

    return ret;
}

std::optional<component::Key> OpenSSL::OpKDF_X963(operation::KDF_X963& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_KDF_CTX* kctx = nullptr;
    const EVP_MD* md = nullptr;
    OSSL_PARAM params[4], *p = params;
    uint8_t* out = util::malloc(op.keySize);

    {
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);

        std::string mdName(EVP_MD_name(md));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdName.data(), mdName.size() + 1);

        auto secretCopy = op.secret.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SECRET,
                secretCopy.data(),
                secretCopy.size());

        auto infoCopy = op.info.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO,
                infoCopy.data(),
                infoCopy.size());

        *p = OSSL_PARAM_construct_end();

        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "X963KDF", nullptr);
            CF_CHECK_NE(kdf, nullptr);
            kctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            CF_CHECK_NE(kctx, nullptr);
        }

        CF_CHECK_GT(EVP_KDF_derive(kctx, out, op.keySize, params), 0);
    }

    /* Finalize */
    {
        ret = component::Key(out, op.keySize);
    }

end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);

    return ret;
}

std::optional<component::Key> OpenSSL::OpKDF_SP_800_108(operation::KDF_SP_800_108& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_KDF_CTX* kctx = nullptr;
    const EVP_MD* md = nullptr;
    OSSL_PARAM params[7], *p = params;
    uint8_t* out = util::malloc(op.keySize);

    std::string hmacStr = "HMAC";
    std::string counterStr = "COUNTER";
    std::string feedbackStr = "FEEDBACK";

    {
        if ( op.mode != 0 && op.mode != 1 ) {
            goto end;
        }

        if ( op.mode == 1 ) {
            /* XXX Salt is ignored in feedback mode
             * https://github.com/openssl/openssl/issues/12409#issuecomment-701645838
             */
            CF_CHECK_EQ(op.salt.GetSize(), 0);
        }

        CF_CHECK_EQ(op.mech.mode, true); /* Currently only HMAC supported, not CMAC */

        CF_CHECK_NE(md = toEVPMD(op.mech.type), nullptr);

        std::string mdName(EVP_MD_name(md));
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, mdName.data(), 0);
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC, hmacStr.data(), 0);

        if ( op.mode == 0 ) {
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, counterStr.data(), 0);
        } else if ( op.mode == 1 ) {
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, feedbackStr.data(), 0);
        } else {
            CF_UNREACHABLE();
        }

        auto secretCopy = op.secret.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY,
                secretCopy.data(),
                secretCopy.size());

        auto labelCopy = op.label.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT,
                labelCopy.data(),
                labelCopy.size());

        auto saltCopy = op.salt.Get();
        *p++ = OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_INFO,
                saltCopy.data(),
                saltCopy.size());

        *p = OSSL_PARAM_construct_end();

        {
            EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "KBKDF", nullptr);
            CF_CHECK_NE(kdf, nullptr);
            kctx = EVP_KDF_CTX_new(kdf);
            EVP_KDF_free(kdf);
            CF_CHECK_NE(kctx, nullptr);
        }

        CF_CHECK_GT(EVP_KDF_derive(kctx, out, op.keySize, params), 0);
    }

    /* Finalize */
    {
        ret = component::Key(out, op.keySize);
    }

end:
    EVP_KDF_CTX_free(kctx);

    util::free(out);

    return ret;
}
#endif

#if !defined(CRYPTOFUZZ_OPENSSL_098)
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
#endif

/* LibreSSL uses getentropy() in ECC operations.
 * MemorySanitizer erroneously does not unpoison the destination buffer.
 * https://github.com/google/sanitizers/issues/1173
 */
#if !(defined(CRYPTOFUZZ_LIBRESSL) && defined(SANITIZER_MSAN))
static std::optional<int> toCurveNID(const component::CurveType& curveType) {
    static const std::map<uint64_t, int> LUT = {
#if !defined(CRYPTOFUZZ_OPENSSL_098)
        { CF_ECC_CURVE("brainpool160r1"), NID_brainpoolP160r1 },
        { CF_ECC_CURVE("brainpool160t1"), NID_brainpoolP160t1 },
        { CF_ECC_CURVE("brainpool192r1"), NID_brainpoolP192r1 },
        { CF_ECC_CURVE("brainpool192t1"), NID_brainpoolP192t1 },
        { CF_ECC_CURVE("brainpool224r1"), NID_brainpoolP224r1 },
        { CF_ECC_CURVE("brainpool224t1"), NID_brainpoolP224t1 },
        { CF_ECC_CURVE("brainpool256r1"), NID_brainpoolP256r1 },
        { CF_ECC_CURVE("brainpool256t1"), NID_brainpoolP256t1 },
        { CF_ECC_CURVE("brainpool320r1"), NID_brainpoolP320r1 },
        { CF_ECC_CURVE("brainpool320t1"), NID_brainpoolP320t1 },
        { CF_ECC_CURVE("brainpool384r1"), NID_brainpoolP384r1 },
        { CF_ECC_CURVE("brainpool384t1"), NID_brainpoolP384t1 },
        { CF_ECC_CURVE("brainpool512r1"), NID_brainpoolP512r1 },
        { CF_ECC_CURVE("brainpool512t1"), NID_brainpoolP512t1 },
#endif
        { CF_ECC_CURVE("secp112r1"), NID_secp112r1 },
        { CF_ECC_CURVE("secp112r2"), NID_secp112r2 },
        { CF_ECC_CURVE("secp128r1"), NID_secp128r1 },
        { CF_ECC_CURVE("secp128r2"), NID_secp128r2 },
        { CF_ECC_CURVE("secp160k1"), NID_secp160k1 },
        { CF_ECC_CURVE("secp160r1"), NID_secp160r1 },
        { CF_ECC_CURVE("secp160r2"), NID_secp160r2 },
        { CF_ECC_CURVE("secp192k1"), NID_secp192k1 },
        { CF_ECC_CURVE("secp224k1"), NID_secp224k1 },
        { CF_ECC_CURVE("secp224r1"), NID_secp224r1 },
        { CF_ECC_CURVE("secp256k1"), NID_secp256k1 },
        { CF_ECC_CURVE("secp384r1"), NID_secp384r1 },
        { CF_ECC_CURVE("secp521r1"), NID_secp521r1 },
        { CF_ECC_CURVE("sect113r1"), NID_sect113r1 },
        { CF_ECC_CURVE("sect113r2"), NID_sect113r2 },
        { CF_ECC_CURVE("sect131r1"), NID_sect131r1 },
        { CF_ECC_CURVE("sect131r2"), NID_sect131r2 },
        { CF_ECC_CURVE("sect163k1"), NID_sect163k1 },
        { CF_ECC_CURVE("sect163r1"), NID_sect163r1 },
        { CF_ECC_CURVE("sect163r2"), NID_sect163r2 },
        { CF_ECC_CURVE("sect193r1"), NID_sect193r1 },
        { CF_ECC_CURVE("sect193r2"), NID_sect193r2 },
        { CF_ECC_CURVE("sect233k1"), NID_sect233k1 },
        { CF_ECC_CURVE("sect233r1"), NID_sect233r1 },
        { CF_ECC_CURVE("sect239k1"), NID_sect239k1 },
        { CF_ECC_CURVE("sect283k1"), NID_sect283k1 },
        { CF_ECC_CURVE("sect283r1"), NID_sect283r1 },
        { CF_ECC_CURVE("sect409k1"), NID_sect409k1 },
        { CF_ECC_CURVE("sect409r1"), NID_sect409r1 },
        { CF_ECC_CURVE("sect571k1"), NID_sect571k1 },
        { CF_ECC_CURVE("sect571r1"), NID_sect571r1 },
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        { CF_ECC_CURVE("sm2p256v1"), NID_sm2 },
#endif
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls1"), NID_wap_wsg_idm_ecid_wtls1 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls10"), NID_wap_wsg_idm_ecid_wtls10 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls11"), NID_wap_wsg_idm_ecid_wtls11 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls12"), NID_wap_wsg_idm_ecid_wtls12 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls3"), NID_wap_wsg_idm_ecid_wtls3 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls4"), NID_wap_wsg_idm_ecid_wtls4 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls5"), NID_wap_wsg_idm_ecid_wtls5 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls6"), NID_wap_wsg_idm_ecid_wtls6 },
#if 0
        /* Incorrectly implemented by OpenSSL:
         * https://github.com/openssl/openssl/issues/6317
         */
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls7"), NID_wap_wsg_idm_ecid_wtls7 },
#endif
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls8"), NID_wap_wsg_idm_ecid_wtls8 },
        { CF_ECC_CURVE("wap_wsg_idm_ecid_wtls9"), NID_wap_wsg_idm_ecid_wtls9 },
        { CF_ECC_CURVE("x962_c2pnb163v1"), NID_X9_62_c2pnb163v1 },
        { CF_ECC_CURVE("x962_c2pnb163v2"), NID_X9_62_c2pnb163v2 },
        { CF_ECC_CURVE("x962_c2pnb163v3"), NID_X9_62_c2pnb163v3 },
        { CF_ECC_CURVE("x962_c2pnb176v1"), NID_X9_62_c2pnb176v1 },
        { CF_ECC_CURVE("x962_c2pnb208w1"), NID_X9_62_c2pnb208w1 },
        { CF_ECC_CURVE("x962_c2pnb272w1"), NID_X9_62_c2pnb272w1 },
        { CF_ECC_CURVE("x962_c2pnb304w1"), NID_X9_62_c2pnb304w1 },
        { CF_ECC_CURVE("x962_c2pnb368w1"), NID_X9_62_c2pnb368w1 },
        { CF_ECC_CURVE("x962_c2tnb191v1"), NID_X9_62_c2tnb191v1 },
        { CF_ECC_CURVE("x962_c2tnb191v2"), NID_X9_62_c2tnb191v2 },
        { CF_ECC_CURVE("x962_c2tnb191v3"), NID_X9_62_c2tnb191v3 },
        { CF_ECC_CURVE("x962_c2tnb239v1"), NID_X9_62_c2tnb239v1 },
        { CF_ECC_CURVE("x962_c2tnb239v2"), NID_X9_62_c2tnb239v2 },
        { CF_ECC_CURVE("x962_c2tnb239v3"), NID_X9_62_c2tnb239v3 },
        { CF_ECC_CURVE("x962_c2tnb359v1"), NID_X9_62_c2tnb359v1 },
        { CF_ECC_CURVE("x962_c2tnb431r1"), NID_X9_62_c2tnb431r1 },
        { CF_ECC_CURVE("secp192r1"), NID_X9_62_prime192v1 },
        { CF_ECC_CURVE("x962_p192v1"), NID_X9_62_prime192v1 },
        { CF_ECC_CURVE("x962_p192v2"), NID_X9_62_prime192v2 },
        { CF_ECC_CURVE("x962_p192v3"), NID_X9_62_prime192v3 },
        { CF_ECC_CURVE("x962_p239v1"), NID_X9_62_prime239v1 },
        { CF_ECC_CURVE("x962_p239v2"), NID_X9_62_prime239v2 },
        { CF_ECC_CURVE("x962_p239v3"), NID_X9_62_prime239v3 },
        { CF_ECC_CURVE("secp256r1"), NID_X9_62_prime256v1 },
        { CF_ECC_CURVE("x962_p256v1"), NID_X9_62_prime256v1 },
#if defined(CRYPTOFUZZ_LIBRESSL)
        { CF_ECC_CURVE("ipsec3"), NID_ipsec3 },
        { CF_ECC_CURVE("ipsec4"), NID_ipsec4 },
        { CF_ECC_CURVE("gostr3410_2001_test"), NID_id_GostR3410_2001_TestParamSet },
        { CF_ECC_CURVE("gostr3410_2001_cryptopro_a"), NID_id_GostR3410_2001_CryptoPro_A_ParamSet },
        { CF_ECC_CURVE("gostr3410_2001_cryptopro_b"), NID_id_GostR3410_2001_CryptoPro_B_ParamSet },
        { CF_ECC_CURVE("gostr3410_2001_cryptopro_c"), NID_id_GostR3410_2001_CryptoPro_C_ParamSet },
        { CF_ECC_CURVE("gostr3410_2001_cryptopro_xcha"), NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet },
        { CF_ECC_CURVE("gostr3410_2001_cryptopro_xchb"), NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet },
        { CF_ECC_CURVE("tc26_gost_3410_12_256_a"), NID_id_tc26_gost_3410_12_256_paramSetA },
        { CF_ECC_CURVE("tc26_gost_3410_12_256_b"), NID_id_tc26_gost_3410_12_256_paramSetB },
        { CF_ECC_CURVE("tc26_gost_3410_12_256_c"), NID_id_tc26_gost_3410_12_256_paramSetC },
        { CF_ECC_CURVE("tc26_gost_3410_12_256_d"), NID_id_tc26_gost_3410_12_256_paramSetD },
        { CF_ECC_CURVE("tc26_gost_3410_12_512_test"), NID_id_tc26_gost_3410_12_512_paramSetTest },
        { CF_ECC_CURVE("tc26_gost_3410_12_512_a"), NID_id_tc26_gost_3410_12_512_paramSetA },
        { CF_ECC_CURVE("tc26_gost_3410_12_512_b"), NID_id_tc26_gost_3410_12_512_paramSetB },
        { CF_ECC_CURVE("tc26_gost_3410_12_512_c"), NID_id_tc26_gost_3410_12_512_paramSetC },
#endif
    };

    if ( LUT.find(curveType.Get()) == LUT.end() ) {
        return std::nullopt;
    }

    return LUT.at(curveType.Get());
}

/* TODO OpenSSL 1.0.2, 0.9.8 */
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::ECC_PublicKey> OpenSSL::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    char* pub_x_str = nullptr;
    char* pub_y_str = nullptr;

    try {
        if ( op.curveType.Get() == CF_ECC_CURVE("x25519") ) {
            uint8_t priv_bytes[32];
            uint8_t pub_bytes[32];
            OpenSSL_bignum::Bignum priv(ds), pub(ds);
            CF_CHECK_EQ(pub.New(), true);

            CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);

            /* Load private key */
            CF_CHECK_NE(BN_bn2binpad(priv.GetPtr(), priv_bytes, sizeof(priv_bytes)), -1);

            /* Private -> public */
            /* noret */ X25519_public_from_private(pub_bytes, priv_bytes);

            /* Convert public key */
            CF_CHECK_NE(BN_bin2bn(pub_bytes, sizeof(pub_bytes), pub.GetDestPtr()), nullptr);

            CF_CHECK_NE(pub_x_str = BN_bn2dec(pub.GetPtr()), nullptr);

            /* Save bignum x/y */
            ret = { std::string(pub_x_str), "0" };
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL)
        } else if ( op.curveType.Get() == CF_ECC_CURVE("x448") ) {
            uint8_t priv_bytes[56];
            uint8_t pub_bytes[56];
            OpenSSL_bignum::Bignum priv(ds), pub(ds);
            CF_CHECK_EQ(pub.New(), true);

            CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);

            /* Load private key */
            CF_CHECK_NE(BN_bn2binpad(priv.GetPtr(), priv_bytes, sizeof(priv_bytes)), -1);

            /* Private -> public */
            /* noret */ X448_public_from_private(pub_bytes, priv_bytes);

            /* Convert public key */
            CF_CHECK_NE(BN_bin2bn(pub_bytes, sizeof(pub_bytes), pub.GetDestPtr()), nullptr);

            CF_CHECK_NE(pub_x_str = BN_bn2dec(pub.GetPtr()), nullptr);

            /* Save bignum x/y */
            ret = { std::string(pub_x_str), "0" };
#endif
        } else {
            CF_EC_KEY key(ds);
            std::shared_ptr<CF_EC_GROUP> group = nullptr;
            OpenSSL_bignum::Bignum prv(ds);
            std::unique_ptr<CF_EC_POINT> pub = nullptr;
            OpenSSL_bignum::Bignum pub_x(ds);
            OpenSSL_bignum::Bignum pub_y(ds);

            {
                std::optional<int> curveNID;
                CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
                CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
                group->Lock();
                CF_CHECK_NE(group->GetPtr(), nullptr);
            }

            CF_CHECK_EQ(EC_KEY_set_group(key.GetPtr(), group->GetPtr()), 1);

            /* Load private key */
            CF_CHECK_EQ(prv.Set(op.priv.ToString(ds)), true);

            /* Set private key */
            CF_CHECK_EQ(EC_KEY_set_private_key(key.GetPtr(), prv.GetPtr()), 1);

            /* Compute public key */
            CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
            CF_CHECK_EQ(EC_POINT_mul(group->GetPtr(), pub->GetPtr(), prv.GetPtr(), nullptr, nullptr, nullptr), 1);

            CF_CHECK_EQ(pub_x.New(), true);
            CF_CHECK_EQ(pub_y.New(), true);

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
            CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), pub->GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);
#else
            CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group->GetPtr(), pub->GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);
#endif

            /* Convert bignum x/y to strings */
            CF_CHECK_NE(pub_x_str = BN_bn2dec(pub_x.GetPtr()), nullptr);
            CF_CHECK_NE(pub_y_str = BN_bn2dec(pub_y.GetPtr()), nullptr);

            /* Save bignum x/y */
            ret = { std::string(pub_x_str), std::string(pub_y_str) };
        }
    } catch ( ... ) { }

end:
    OPENSSL_free(pub_x_str);
    OPENSSL_free(pub_y_str);

    global_ds = nullptr;

    return ret;
}
#endif /* CRYPTOFUZZ_OPENSSL_102, CRYPTOFUZZ_OPENSSL_098 */

std::optional<component::ECC_KeyPair> OpenSSL::OpECC_GenerateKeyPair(operation::ECC_GenerateKeyPair& op) {
    std::optional<component::ECC_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    EC_KEY* key = nullptr;
    char* priv_str = nullptr;
    BIGNUM* pub_x = nullptr;
    BIGNUM* pub_y = nullptr;
    char* pub_x_str = nullptr;
    char* pub_y_str = nullptr;

    try {
        const BIGNUM* priv = nullptr;
        std::shared_ptr<CF_EC_GROUP> group = nullptr;
        std::unique_ptr<CF_EC_POINT> pub = nullptr;

        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(key = EC_KEY_new_by_curve_name(*curveNID), nullptr);
        CF_CHECK_EQ(EC_KEY_generate_key(key), 1);

        /* Private key */
        {
            CF_CHECK_NE(priv = EC_KEY_get0_private_key(key), nullptr);
            CF_CHECK_NE(priv_str = BN_bn2dec(priv), nullptr);
        }

        /* Public key */
        {
            CF_CHECK_NE(pub_x = BN_new(), nullptr);
            CF_CHECK_NE(pub_y = BN_new(), nullptr);
            CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
            group->Lock();
            CF_CHECK_NE(group->GetPtr(), nullptr);
            CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
            CF_CHECK_EQ(EC_POINT_mul(group->GetPtr(), pub->GetPtr(), priv, nullptr, nullptr, nullptr), 1);

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
            CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), pub->GetPtr(), pub_x, pub_y, nullptr), 0);
#else
            CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group->GetPtr(), pub->GetPtr(), pub_x, pub_y, nullptr), 0);
#endif

            CF_CHECK_NE(pub_x_str = BN_bn2dec(pub_x), nullptr);
            CF_CHECK_NE(pub_y_str = BN_bn2dec(pub_y), nullptr);
        }

        {
            ret = {
                std::string(priv_str),
                { std::string(pub_x_str), std::string(pub_y_str) }
            };
        }
    } catch ( ... ) { }

end:
    EC_KEY_free(key);
    OPENSSL_free(priv_str);
    BN_free(pub_x);
    BN_free(pub_y);
    OPENSSL_free(pub_x_str);
    OPENSSL_free(pub_y_str);

    global_ds = nullptr;

    return ret;
}

std::optional<bool> OpenSSL::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    CF_EC_KEY key(ds);
    std::shared_ptr<CF_EC_GROUP> group = nullptr;

    std::unique_ptr<CF_EC_POINT> pub = nullptr;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    CF_CHECK_EQ(EC_KEY_set_group(key.GetPtr(), group->GetPtr()), 1);

    /* Construct key */
    CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(pub->Set(op.pub.first, op.pub.second, false,
                /* allowProjective */
#if defined(CRYPTOFUZZ_LIBRESSL)
                /* https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=55750 */
                true
#else
                false
#endif
    ));

    /* Reject oversized pubkeys until it is fixed in OpenSSL
     * https://github.com/openssl/openssl/issues/17590
     */
    {
        const auto order = cryptofuzz::repository::ECC_CurveToOrder(op.curveType.Get());
        CF_CHECK_NE(order, std::nullopt);
        CF_CHECK_TRUE(op.pub.first.IsLessThan(*order));
        CF_CHECK_TRUE(op.pub.second.IsLessThan(*order));
    }

    ret = EC_KEY_set_public_key(key.GetPtr(), pub->GetPtr()) == 1;
end:
    return ret;
}

/* TODO OpenSSL 1.0.2, 0.9.8 */
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::ECDSA_Signature> OpenSSL::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    ECDSA_SIG* signature = nullptr;
    char* pub_x_str = nullptr;
    char* pub_y_str = nullptr;
    char* sig_r_str = nullptr;
    char* sig_s_str = nullptr;

    try {
        CF_EC_KEY key(ds);
        std::shared_ptr<CF_EC_GROUP> group = nullptr;
        OpenSSL_bignum::Bignum prv(ds);
        std::unique_ptr<CF_EC_POINT> pub = nullptr;
        OpenSSL_bignum::Bignum pub_x(ds);
        OpenSSL_bignum::Bignum pub_y(ds);
        const BIGNUM *R = nullptr, *S = nullptr;

#if defined(CRYPTOFUZZ_BORINGSSL)
        CF_CHECK_TRUE(op.UseRandomNonce() || op.UseSpecifiedNonce());
#else
        CF_CHECK_TRUE(op.UseRandomNonce());
#endif
        CF_CHECK_TRUE(op.digestType.Is(CF_DIGEST("NULL")));

        {
            std::optional<int> curveNID;
            CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
            CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
            group->Lock();
            CF_CHECK_NE(group->GetPtr(), nullptr);
        }

        CF_CHECK_EQ(EC_KEY_set_group(key.GetPtr(), group->GetPtr()), 1);

        /* Load private key */
        CF_CHECK_EQ(prv.Set(op.priv.ToString(ds)), true);

        /* Set private key */
        CF_CHECK_EQ(EC_KEY_set_private_key(key.GetPtr(), prv.GetPtr()), 1);

        /* Compute public key */
        CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
        CF_CHECK_EQ(EC_POINT_mul(group->GetPtr(), pub->GetPtr(), prv.GetPtr(), nullptr, nullptr, nullptr), 1);

        CF_CHECK_EQ(pub_x.New(), true);
        CF_CHECK_EQ(pub_y.New(), true);

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110)
        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), pub->GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);
#else
        CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group->GetPtr(), pub->GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);
#endif

        CF_CHECK_NE(pub_x_str = BN_bn2dec(pub_x.GetPtr()), nullptr);
        CF_CHECK_NE(pub_y_str = BN_bn2dec(pub_y.GetPtr()), nullptr);

        const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);

#if defined(CRYPTOFUZZ_BORINGSSL)
        if ( op.UseSpecifiedNonce() ) {
            std::optional<std::vector<uint8_t>> nonce_bytes;
            CF_CHECK_NE(nonce_bytes = util::DecToBin(op.nonce.ToTrimmedString()), std::nullopt);

            CF_CHECK_NE(signature = ECDSA_sign_with_nonce_and_leak_private_key_for_testing(CT.GetPtr(), CT.GetSize(), key.GetPtr(), nonce_bytes->data(), nonce_bytes->size()), nullptr);
        }
        else
#endif
        CF_CHECK_NE(signature = ECDSA_do_sign(CT.GetPtr(), CT.GetSize(), key.GetPtr()), nullptr);

#if defined(CRYPTOFUZZ_LIBRESSL)
        /* noret */ ECDSA_SIG_get0(signature, &R, &S);
        CF_CHECK_NE(R, nullptr);
        CF_CHECK_NE(S, nullptr);
#else
        CF_CHECK_NE(R = ECDSA_SIG_get0_r(signature), nullptr);
        CF_CHECK_NE(S = ECDSA_SIG_get0_s(signature), nullptr);
#endif

        /* Convert bignum x/y to strings */
        CF_CHECK_NE(sig_r_str = BN_bn2dec(R), nullptr);
        CF_CHECK_NE(sig_s_str = BN_bn2dec(S), nullptr);


        component::Bignum S_corrected{std::string(sig_s_str)};
        CF_NORET(util::AdjustECDSASignature(op.curveType.Get(), S_corrected));

        ret = { {sig_r_str, S_corrected.ToTrimmedString()}, {pub_x_str, pub_y_str} };
    } catch ( ... ) { }

end:
    if ( signature != nullptr ) {
        ECDSA_SIG_free(signature);
    }
    OPENSSL_free(pub_x_str);
    OPENSSL_free(pub_y_str);
    OPENSSL_free(sig_r_str);
    OPENSSL_free(sig_s_str);

    global_ds = nullptr;

    return ret;
}
#endif /* CRYPTOFUZZ_OPENSSL_102, CRYPTOFUZZ_OPENSSL_098 */

std::optional<bool> OpenSSL::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    ECDSA_SIG* signature = nullptr;

    try {
        CF_EC_KEY key(ds);
        std::shared_ptr<CF_EC_GROUP> group = nullptr;

        std::unique_ptr<CF_EC_POINT> pub = nullptr;

        OpenSSL_bignum::Bignum sig_s(ds);
        OpenSSL_bignum::Bignum sig_r(ds);

        /* Initialize */
        {
            {
                std::optional<int> curveNID;
                CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
                CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
                group->Lock();
                CF_CHECK_NE(group->GetPtr(), nullptr);
            }
            CF_CHECK_EQ(EC_KEY_set_group(key.GetPtr(), group->GetPtr()), 1);

            /* Construct signature */
            CF_CHECK_EQ(sig_r.Set(op.signature.signature.first.ToString(ds)), true);
            CF_CHECK_EQ(sig_s.Set(op.signature.signature.second.ToString(ds)), true);
            CF_CHECK_NE(signature = ECDSA_SIG_new(), nullptr);
#if defined(CRYPTOFUZZ_OPENSSL_102) || defined(CRYPTOFUZZ_OPENSSL_098)
            BN_free(signature->r);
            BN_free(signature->s);
            signature->r = sig_r.GetPtrConst();
            signature->s = sig_s.GetPtrConst();
#else
            CF_CHECK_EQ(ECDSA_SIG_set0(signature, sig_r.GetDestPtr(false), sig_s.GetDestPtr(false)), 1);
#endif
            /* 'signature' now has ownership, and the BIGNUMs will be freed by ECDSA_SIG_free */
            sig_r.ReleaseOwnership();
            sig_s.ReleaseOwnership();

            /* Construct key */
            CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
            CF_CHECK_TRUE(pub->Set(op.signature.pub.first, op.signature.pub.second, false));
            CF_CHECK_EQ(EC_KEY_set_public_key(key.GetPtr(), pub->GetPtr()), 1);
        }

        /* Process */
        {
            int res;
            if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
                const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
                res = ECDSA_do_verify(CT.GetPtr(), CT.GetSize(), signature, key.GetPtr());
            } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
                uint8_t CT[32];
                SHA256(op.cleartext.GetPtr(), op.cleartext.GetSize(), CT);
                res = ECDSA_do_verify(CT, sizeof(CT), signature, key.GetPtr());
            } else {
                /* TODO other digests */
                goto end;
            }

            if ( res == 0 ) {
                ret = false;
            } else if ( res == 1 ) {
                ret = true;
            } else {
                /* ECDSA_do_verify failed -- don't set ret */
            }

        }
    } catch ( ... ) { }

end:
    if ( signature != nullptr ) {
        ECDSA_SIG_free(signature);
    }

    global_ds = nullptr;

    return ret;
}

std::optional<component::Secret> OpenSSL::OpECDH_Derive(operation::ECDH_Derive& op) {
    std::optional<component::Secret> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());


    CF_EC_KEY key(ds);
    OpenSSL_bignum::Bignum prv(ds);
    std::shared_ptr<CF_EC_GROUP> group = nullptr;
    std::unique_ptr<CF_EC_POINT> pub = nullptr;
    uint8_t* secret = nullptr;
    int secret_len;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    /* Load private key */
    {
        CF_CHECK_EQ(EC_KEY_set_group(key.GetPtr(), group->GetPtr()), 1);

        /* Load private key */
        CF_CHECK_EQ(prv.Set(op.priv.ToString(ds)), true);

        /* Set private key */
        CF_CHECK_EQ(EC_KEY_set_private_key(key.GetPtr(), prv.GetPtr()), 1);
    }

    /* Load public key */
    {
        CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
        CF_CHECK_TRUE(pub->Set(op.pub.first, op.pub.second, false, false));
    }

#if 0
    secret_len = ECDH_compute_key(
            nullptr, 0, pub->GetPtr(), key.GetPtr(), nullptr);
    CF_CHECK_GT(secret_len, 0);
    abort();
#endif

    secret_len = 1024;
    secret = util::malloc(secret_len);

    secret_len = ECDH_compute_key(
             secret,
             1024,
             pub->GetPtr(),
             key.GetPtr(), nullptr);
    CF_CHECK_GT(secret_len, 0);

    ret = component::Secret(Buffer(secret, secret_len));

end:
    util::free(secret);

    return ret;
}

/* TODO OpenSSL 1.0.2, 0.9.8 */
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::DH_KeyPair> OpenSSL::OpDH_GenerateKeyPair(operation::DH_GenerateKeyPair& op) {
    std::optional<component::DH_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    DH* dh = nullptr;
    char* priv_str = nullptr;
    char* pub_str = nullptr;

    CF_CHECK_NE(dh = DH_new(), nullptr);

    try {
        OpenSSL_bignum::Bignum prime(ds), base(ds);
        /* Set prime and base */
        {
            CF_CHECK_EQ(prime.Set(op.prime.ToString(ds)), true);
            CF_CHECK_EQ(base.Set(op.base.ToString(ds)), true);

            CF_CHECK_EQ(DH_set0_pqg(dh, prime.GetPtrConst(), nullptr, base.GetPtrConst()), 1);
            prime.ReleaseOwnership();
            base.ReleaseOwnership();
        }

        CF_CHECK_EQ(DH_generate_key(dh), 1);

        {
            const BIGNUM* priv = nullptr, *pub = nullptr;
            /* noret */ DH_get0_key(dh, &priv, &pub);
            CF_CHECK_NE(priv, nullptr);
            CF_CHECK_NE(pub, nullptr);

            CF_CHECK_NE(priv_str = BN_bn2dec(priv), nullptr);
            CF_CHECK_NE(pub_str = BN_bn2dec(pub), nullptr);
        }

        ret = { std::string(priv_str), std::string(pub_str) };
    } catch ( ... ) { }

end:
    DH_free(dh);
    OPENSSL_free(priv_str);
    OPENSSL_free(pub_str);

    global_ds = nullptr;

    return ret;
}
#endif /* CRYPTOFUZZ_OPENSSL_102, CRYPTOFUZZ_OPENSSL_098 */

/* TODO OpenSSL 1.0.2, 0.9.8 */
#if !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_098)
std::optional<component::Bignum> OpenSSL::OpDH_Derive(operation::DH_Derive& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    DH* dh = nullptr;
    OpenSSL_bignum::Bignum prime(ds), base(ds), priv(ds), pub(ds), derived(ds);
    uint8_t* derived_bytes = nullptr;
    int derived_size;

    CF_CHECK_NE(op.priv.ToTrimmedString(), "0");
    CF_CHECK_NE(dh = DH_new(), nullptr);

    /* Set prime, base and private key */
    {
        CF_CHECK_EQ(prime.Set(op.prime.ToString(ds)), true);
        CF_CHECK_EQ(base.Set(op.base.ToString(ds)), true);

        CF_CHECK_EQ(DH_set0_pqg(dh, prime.GetPtrConst(), nullptr, base.GetPtrConst()), 1);
        prime.ReleaseOwnership();
        base.ReleaseOwnership();

        CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);
        CF_CHECK_EQ(DH_set0_key(dh, nullptr, priv.GetPtrConst()), 1);
        priv.ReleaseOwnership();
    }

    derived_size = DH_size(dh);
    derived_bytes = util::malloc(derived_size);

    CF_CHECK_EQ(pub.Set(op.pub.ToString(ds)), true);

    CF_CHECK_NE(derived_size = DH_compute_key(derived_bytes, pub.GetPtr(), dh), -1);

    CF_CHECK_EQ(derived.New(), true);
    CF_CHECK_NE(BN_bin2bn(derived_bytes, derived_size, derived.GetDestPtr()), nullptr);

    CF_CHECK_EQ(BN_is_zero(derived.GetPtr()), 0);

    ret = derived.ToComponentBignum();

end:
    DH_free(dh);
    util::free(derived_bytes);
    return ret;
}
#endif /* CRYPTOFUZZ_OPENSSL_102, CRYPTOFUZZ_OPENSSL_098 */

std::optional<component::Bignum> OpenSSL::OpDSA_PrivateToPublic(operation::DSA_PrivateToPublic& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;
    OpenSSL_bignum::Bignum priv(ds);
    DSA* dsa = nullptr;
    char* str;
    const BIGNUM* pub = nullptr;
    std::string pub_str;

    CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);

    CF_CHECK_NE(dsa = DSA_new(), nullptr);
    CF_CHECK_NE(DSA_set0_key(dsa, nullptr, priv.GetDestPtr()), 0);
    priv.ReleaseOwnership();

    CF_CHECK_NE(DSA_generate_key(dsa), 0);
    CF_NORET(DSA_get0_key(dsa, &pub, nullptr));
    CF_CHECK_NE(str = BN_bn2dec(pub), nullptr);
    pub_str = str;
    OPENSSL_free(str);

    ret = pub_str;

end:

    CF_NORET(DSA_free(dsa));

    global_ds = nullptr;

    return ret;
}

std::optional<component::DSA_Parameters> OpenSSL::OpDSA_GenerateParameters(operation::DSA_GenerateParameters& op) {
    (void)op;
    std::optional<component::DSA_Parameters> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    DSA* dsa = nullptr;

    CF_CHECK_NE(dsa = DSA_new(), nullptr);
    CF_CHECK_NE(DSA_generate_parameters_ex(dsa, 1024, NULL, 0, NULL, NULL, NULL), 0);

    {
        std::string p_str, q_str, g_str;

        char* str;

        CF_CHECK_NE(str = BN_bn2dec(DSA_get0_p(dsa)), nullptr);
        p_str = str;
        OPENSSL_free(str);

        CF_CHECK_NE(str = BN_bn2dec(DSA_get0_q(dsa)), nullptr);
        q_str = str;
        OPENSSL_free(str);

        CF_CHECK_NE(str = BN_bn2dec(DSA_get0_g(dsa)), nullptr);
        g_str = str;
        OPENSSL_free(str);

        ret = { p_str, q_str, g_str };
    }

end:
    CF_NORET(DSA_free(dsa));

    global_ds = nullptr;

    return ret;
}

std::optional<component::DSA_Signature> OpenSSL::OpDSA_Sign(operation::DSA_Sign& op) {
    std::optional<component::DSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    DSA* dsa = nullptr;
    DSA_SIG* dsa_sig = nullptr;
    uint8_t* signature = nullptr;
    unsigned int signature_len;
    OpenSSL_bignum::Bignum p(ds), q(ds), g(ds), pub(ds), priv(ds);
    std::string r_str, s_str, pub_str;

    CF_CHECK_EQ(p.Set(op.parameters.p.ToString(ds)), true);
    CF_CHECK_EQ(q.Set(op.parameters.q.ToString(ds)), true);
    CF_CHECK_EQ(g.Set(op.parameters.g.ToString(ds)), true);
    CF_CHECK_TRUE(pub.New());
    CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);

    CF_CHECK_NE(dsa = DSA_new(), nullptr);

    CF_CHECK_NE(DSA_set0_pqg(dsa, p.GetDestPtr(), q.GetDestPtr(), g.GetDestPtr()), 0);

    p.ReleaseOwnership();
    q.ReleaseOwnership();
    g.ReleaseOwnership();

    CF_CHECK_NE(DSA_set0_key(dsa, pub.GetDestPtr(), priv.GetDestPtr()), 0);
    pub.ReleaseOwnership();
    priv.ReleaseOwnership();

    signature = util::malloc(DSA_size(dsa));
    CF_CHECK_NE(DSA_sign(
                0,
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                signature, &signature_len,
                dsa), 0);

    {
        const uint8_t* p = signature;
        CF_CHECK_NE(dsa_sig = d2i_DSA_SIG(nullptr, &p, signature_len), nullptr);
        const BIGNUM *r, *s;
        CF_NORET(DSA_SIG_get0(dsa_sig, &r, &s));

        char* str;
        CF_CHECK_NE(str = BN_bn2dec(r), nullptr);
        r_str = str;
        OPENSSL_free(str);

        CF_CHECK_NE(str = BN_bn2dec(s), nullptr);
        s_str = str;
        OPENSSL_free(str);

        CF_CHECK_NE(DSA_generate_key(dsa), 0);
        const BIGNUM* pub = nullptr;
        CF_NORET(DSA_get0_key(dsa, &pub, nullptr));
        CF_CHECK_NE(str = BN_bn2dec(pub), nullptr);
        pub_str = str;
        OPENSSL_free(str);

        ret = component::DSA_Signature({r_str, s_str}, pub_str);
    }

end:
    CF_NORET(DSA_free(dsa));
    CF_NORET(DSA_SIG_free(dsa_sig));
    util::free(signature);

    global_ds = nullptr;

    return ret;
}

std::optional<bool> OpenSSL::OpDSA_Verify(operation::DSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    DSA* dsa = nullptr;
    DSA_SIG* dsa_sig = nullptr;
    uint8_t* signature = nullptr;
    OpenSSL_bignum::Bignum p(ds), q(ds), g(ds), r(ds), s(ds), pub(ds);
    std::string r_str, s_str, pub_str;

    CF_CHECK_EQ(p.Set(op.parameters.p.ToString(ds)), true);
    CF_CHECK_EQ(q.Set(op.parameters.q.ToString(ds)), true);
    CF_CHECK_EQ(g.Set(op.parameters.g.ToString(ds)), true);
    CF_CHECK_EQ(r.Set(op.signature.first.ToString(ds)), true);
    CF_CHECK_EQ(s.Set(op.signature.second.ToString(ds)), true);
    CF_CHECK_EQ(pub.Set(op.pub.ToString(ds)), true);

    CF_CHECK_NE(dsa = DSA_new(), nullptr);

    CF_CHECK_NE(DSA_set0_pqg(dsa, p.GetDestPtr(), q.GetDestPtr(), g.GetDestPtr()), 0);

    p.ReleaseOwnership();
    q.ReleaseOwnership();
    g.ReleaseOwnership();

    CF_CHECK_NE(DSA_set0_key(dsa, pub.GetDestPtr(), nullptr), 0);
    pub.ReleaseOwnership();

    {
        CF_CHECK_NE(dsa_sig = DSA_SIG_new(), nullptr);

        CF_CHECK_NE(DSA_SIG_set0(dsa_sig, r.GetDestPtr(), s.GetDestPtr()), 0);
        r.ReleaseOwnership();
        s.ReleaseOwnership();

        const auto siglen = i2d_DSA_SIG(dsa_sig, &signature);
        CF_CHECK_GT(siglen, 0);

        const auto r = DSA_verify(
                0,
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                signature, siglen,
                dsa);

        CF_CHECK_NE(r, -1);

        ret = r;
    }

end:
    CF_NORET(DSA_free(dsa));
    CF_NORET(DSA_SIG_free(dsa_sig));
    OPENSSL_free(signature);

    global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> OpenSSL::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    std::shared_ptr<CF_EC_GROUP> group = nullptr;
    std::unique_ptr<CF_EC_POINT> a = nullptr, b = nullptr, res = nullptr;
    char* x_str = nullptr;
    char* y_str = nullptr;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(b = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(b->Set(op.b.first, op.b.second));

    CF_CHECK_NE(res = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);

    CF_CHECK_NE(EC_POINT_add(group->GetPtr(), res->GetPtr(), a->GetPtr(), b->GetPtr(), nullptr), 0);

    if ( a->IsProjective() ) {
        OpenSSL_bignum::BN_CTX ctx(ds);
        if ( !EC_POINT_is_on_curve(group->GetPtr(), a->GetPtr(), ctx.GetPtr()) ) {
            goto end;
        }
    }

    if ( b->IsProjective() ) {
        OpenSSL_bignum::BN_CTX ctx(ds);
        if ( !EC_POINT_is_on_curve(group->GetPtr(), b->GetPtr(), ctx.GetPtr()) ) {
            goto end;
        }
    }

    {
        OpenSSL_bignum::Bignum x(ds);
        OpenSSL_bignum::Bignum y(ds);

        CF_CHECK_EQ(x.New(), true);
        CF_CHECK_EQ(y.New(), true);

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), res->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);
#else
        CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group->GetPtr(), res->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);
#endif

        /* Convert bignum x/y to strings */
        CF_CHECK_NE(x_str = BN_bn2dec(x.GetPtr()), nullptr);
        CF_CHECK_NE(y_str = BN_bn2dec(y.GetPtr()), nullptr);

        ret = { std::string(x_str), std::string(y_str) };
    }

end:
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);

    global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> OpenSSL::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    std::shared_ptr<CF_EC_GROUP> group = nullptr;
    std::unique_ptr<CF_EC_POINT> a = nullptr, res = nullptr;
    OpenSSL_bignum::Bignum b(ds);
    char* x_str = nullptr;
    char* y_str = nullptr;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(res = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);

    CF_CHECK_EQ(b.Set(op.b.ToString(ds)), true);

#if !defined(CRYPTOFUZZ_BORINGSSL)
    {
        bool precompute = false;
        try {
            precompute = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData& ) {
        }

        if ( precompute == true ) {
            CF_CHECK_NE(EC_GROUP_precompute_mult(group->GetPtr(), nullptr), 0);
        }
    }
#endif

    CF_CHECK_NE(EC_POINT_mul(group->GetPtr(), res->GetPtr(), nullptr, a->GetPtr(), b.GetPtr(), nullptr), 0);

    if ( op.b.ToTrimmedString() == "0" ) {
        if ( !a->IsProjective() ) {
            CF_ASSERT(
                    EC_POINT_is_at_infinity(group->GetPtr(), res->GetPtr()) == 1,
                    "Point multiplication by 0 does not yield point at infinity");
        }
    }

    /* Bug */
#if !defined(CRYPTOFUZZ_OPENSSL_098)
    {
        if ( !a->IsProjective() ) {
            OpenSSL_bignum::BN_CTX ctx(ds);

            if ( !EC_POINT_is_on_curve(group->GetPtr(), a->GetPtr(), ctx.GetPtr()) ) {
                CF_ASSERT(
                        EC_POINT_is_on_curve(group->GetPtr(), res->GetPtr(), ctx.GetPtr()) == 0,
                        "Point multiplication of invalid point yields valid point");
            }
        }
    }
#endif

    if ( a->IsProjective() ) {
        OpenSSL_bignum::BN_CTX ctx(ds);
        if ( !EC_POINT_is_on_curve(group->GetPtr(), a->GetPtr(), ctx.GetPtr()) ) {
            goto end;
        }
    }

    ret = res->Get();

end:
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);

    global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> OpenSSL::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::shared_ptr<CF_EC_GROUP> group = nullptr;
    std::unique_ptr<CF_EC_POINT> a = nullptr, res = nullptr;
    char* x_str = nullptr;
    char* y_str = nullptr;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(EC_POINT_invert(group->GetPtr(), a->GetPtr(), nullptr), 0);

    {
        OpenSSL_bignum::Bignum x(ds);
        OpenSSL_bignum::Bignum y(ds);

        CF_CHECK_EQ(x.New(), true);
        CF_CHECK_EQ(y.New(), true);

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), a->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);
#else
        CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group->GetPtr(), a->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);
#endif

        /* Convert bignum x/y to strings */
        CF_CHECK_NE(x_str = BN_bn2dec(x.GetPtr()), nullptr);
        CF_CHECK_NE(y_str = BN_bn2dec(y.GetPtr()), nullptr);

        ret = { std::string(x_str), std::string(y_str) };
    }

end:
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);

    return ret;
}

std::optional<component::ECC_Point> OpenSSL::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    std::shared_ptr<CF_EC_GROUP> group = nullptr;
    std::unique_ptr<CF_EC_POINT> a = nullptr, res = nullptr;
    char* x_str = nullptr;
    char* y_str = nullptr;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(res = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);

    CF_CHECK_NE(EC_POINT_dbl(group->GetPtr(), res->GetPtr(), a->GetPtr(), nullptr), 0);

    {
        OpenSSL_bignum::Bignum x(ds);
        OpenSSL_bignum::Bignum y(ds);

        CF_CHECK_EQ(x.New(), true);
        CF_CHECK_EQ(y.New(), true);

#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102) && !defined(CRYPTOFUZZ_OPENSSL_110) && !defined(CRYPTOFUZZ_OPENSSL_098)
        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), res->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);
#else
        CF_CHECK_NE(EC_POINT_get_affine_coordinates_GFp(group->GetPtr(), res->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);
#endif

        /* Convert bignum x/y to strings */
        CF_CHECK_NE(x_str = BN_bn2dec(x.GetPtr()), nullptr);
        CF_CHECK_NE(y_str = BN_bn2dec(y.GetPtr()), nullptr);

        ret = { std::string(x_str), std::string(y_str) };
    }

end:
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);

    global_ds = nullptr;

    return ret;
}

std::optional<bool> OpenSSL::OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    std::shared_ptr<CF_EC_GROUP> group = nullptr;
    std::unique_ptr<CF_EC_POINT> a = nullptr, b = nullptr;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(b = std::make_unique<CF_EC_POINT>(ds, group, op.curveType.Get()), nullptr);
    CF_CHECK_TRUE(b->Set(op.b.first, op.b.second));

    ret = EC_POINT_cmp(group->GetPtr(), a->GetPtr(), b->GetPtr(), nullptr) == 0;

end:
    global_ds = nullptr;

    return ret;
}

std::optional<component::Bignum> OpenSSL::OpBignumCalc(operation::BignumCalc& op) {
    bool prime_modulus = false;

    if ( op.modulo != std::nullopt ) {
        if ( op.calcOp.Get() != CF_CALCOP("Sqrt(A)") ) {
            return std::nullopt;
        }

        if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
            prime_modulus = true;
        } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
            prime_modulus = true;
        } else {
            return std::nullopt;
        }
    }

    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    global_ds = &ds;

    try {
        OpenSSL_bignum::BN_CTX ctx(ds);
        OpenSSL_bignum::BignumCluster bn(ds,
                OpenSSL_bignum::Bignum(ds),
                OpenSSL_bignum::Bignum(ds),
                OpenSSL_bignum::Bignum(ds),
                OpenSSL_bignum::Bignum(ds));

        OpenSSL_bignum::Bignum res(ds);

        std::unique_ptr<OpenSSL_bignum::Operation> opRunner = nullptr;

        CF_CHECK_EQ(res.New(), true);
        CF_CHECK_EQ(bn.New(0), true);
        CF_CHECK_EQ(bn.New(1), true);
        CF_CHECK_EQ(bn.New(2), true);
        CF_CHECK_EQ(bn.New(3), true);

        CF_NORET(res.Randomize());
        CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
        if ( prime_modulus == false ) {
            CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
        } else {
            CF_CHECK_EQ(bn.Set(1, op.modulo->ToString(ds)), true);
        }
        CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
        CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Add>();
                break;
            case    CF_CALCOP("Sub(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Sub>();
                break;
            case    CF_CALCOP("Mul(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mul>();
                break;
            case    CF_CALCOP("Mod(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mod>();
                break;
            case    CF_CALCOP("ExpMod(A,B,C)"):
                opRunner = std::make_unique<OpenSSL_bignum::ExpMod>();
                break;
            case    CF_CALCOP("Sqr(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Sqr>();
                break;
            case    CF_CALCOP("GCD(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::GCD>();
                break;
            case    CF_CALCOP("AddMod(A,B,C)"):
                opRunner = std::make_unique<OpenSSL_bignum::AddMod>();
                break;
            case    CF_CALCOP("SubMod(A,B,C)"):
                opRunner = std::make_unique<OpenSSL_bignum::SubMod>();
                break;
            case    CF_CALCOP("MulMod(A,B,C)"):
                opRunner = std::make_unique<OpenSSL_bignum::MulMod>();
                break;
            case    CF_CALCOP("SqrMod(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::SqrMod>();
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::InvMod>();
                break;
            case    CF_CALCOP("Cmp(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Cmp>();
                break;
            case    CF_CALCOP("Div(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Div>();
                break;
            case    CF_CALCOP("IsPrime(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsPrime>();
                break;
            case    CF_CALCOP("Sqrt(A)"):
                if ( prime_modulus == false ) {
                    opRunner = std::make_unique<OpenSSL_bignum::Sqrt>();
                } else {
                    opRunner = std::make_unique<OpenSSL_bignum::SqrtMod>();
                }
                break;
            case    CF_CALCOP("IsNeg(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsNeg>();
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsEq>();
                break;
            case    CF_CALCOP("IsEven(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsEven>();
                break;
            case    CF_CALCOP("IsOdd(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsOdd>();
                break;
            case    CF_CALCOP("IsZero(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsZero>();
                break;
            case    CF_CALCOP("IsOne(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsOne>();
                break;
            case    CF_CALCOP("Jacobi(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Jacobi>();
                break;
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_OPENSSL_098) && !defined(CRYPTOFUZZ_LIBRESSL)
            case    CF_CALCOP("Mod_NIST_192(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_192>();
                break;
            case    CF_CALCOP("Mod_NIST_224(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_224>();
                break;
            case    CF_CALCOP("Mod_NIST_256(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_256>();
                break;
            case    CF_CALCOP("Mod_NIST_384(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_384>();
                break;
            case    CF_CALCOP("Mod_NIST_521(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_521>();
                break;
#endif
#if defined(CRYPTOFUZZ_BORINGSSL)
            case    CF_CALCOP("LCM(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::LCM>();
                break;
#endif
            case    CF_CALCOP("Exp(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Exp>();
                break;
            case    CF_CALCOP("Abs(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Abs>();
                break;
            case    CF_CALCOP("RShift(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::RShift>();
                break;
            case    CF_CALCOP("LShift1(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::LShift1>();
                break;
            case    CF_CALCOP("SetBit(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::SetBit>();
                break;
            case    CF_CALCOP("ClearBit(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::ClearBit>();
                break;
            case    CF_CALCOP("Bit(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Bit>();
                break;
            case    CF_CALCOP("CmpAbs(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::CmpAbs>();
                break;
            case    CF_CALCOP("ModLShift(A,B,C)"):
                opRunner = std::make_unique<OpenSSL_bignum::ModLShift>();
                break;
            case    CF_CALCOP("IsPow2(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsPow2>();
                break;
            case    CF_CALCOP("Mask(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::Mask>();
                break;
            case    CF_CALCOP("IsCoprime(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsCoprime>();
                break;
            case    CF_CALCOP("Rand()"):
                opRunner = std::make_unique<OpenSSL_bignum::Rand>();
                break;
            case    CF_CALCOP("IsSquare(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::IsSquare>();
                break;
            case    CF_CALCOP("Neg(A)"):
                opRunner = std::make_unique<OpenSSL_bignum::Neg>();
                break;
            case    CF_CALCOP("RandRange(A,B)"):
                opRunner = std::make_unique<OpenSSL_bignum::RandRange>();
                break;
        }

        CF_CHECK_NE(opRunner, nullptr);
        CF_CHECK_EQ(opRunner->Run(ds, res, bn, ctx), true);

        ret = res.ToComponentBignum();
    } catch ( ... ) { }

end:
    global_ds = nullptr;

    return ret;
}

bool OpenSSL::SupportsModularBignumCalc(void) const {
    return true;
}

#endif

} /* namespace module */
} /* namespace cryptofuzz */
