#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace module {

mbedTLS::mbedTLS(void) :
    Module("mbed TLS") { }

const mbedtls_cipher_info_t* mbedTLS::to_mbedtls_cipher_info_t(const component::SymmetricCipherType cipherType) const {
    using fuzzing::datasource::ID;

    switch ( cipherType.Get() ) {
        case ID("Cryptofuzz/Cipher/AES_128_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
        case ID("Cryptofuzz/Cipher/AES_192_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
        case ID("Cryptofuzz/Cipher/AES_256_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
        case ID("Cryptofuzz/Cipher/AES_128_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
        case ID("Cryptofuzz/Cipher/AES_192_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CBC);
        case ID("Cryptofuzz/Cipher/AES_256_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
        case ID("Cryptofuzz/Cipher/AES_128_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
        case ID("Cryptofuzz/Cipher/AES_192_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CTR);
        case ID("Cryptofuzz/Cipher/AES_256_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
        case ID("Cryptofuzz/Cipher/AES_128_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
        case ID("Cryptofuzz/Cipher/AES_192_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_GCM);
        case ID("Cryptofuzz/Cipher/AES_256_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_ECB);
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_ECB);
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_ECB);
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_CBC);
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_CBC);
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_CBC);
        case ID("Cryptofuzz/Cipher/CAMELLIA_128_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_CTR);
        case ID("Cryptofuzz/Cipher/CAMELLIA_192_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_CTR);
        case ID("Cryptofuzz/Cipher/CAMELLIA_256_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_CTR);
        case ID("Cryptofuzz/Cipher/ARIA_128_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_ECB);
        case ID("Cryptofuzz/Cipher/ARIA_192_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_ECB);
        case ID("Cryptofuzz/Cipher/ARIA_256_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_ECB);
        case ID("Cryptofuzz/Cipher/ARIA_128_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_CBC);
        case ID("Cryptofuzz/Cipher/ARIA_192_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_CBC);
        case ID("Cryptofuzz/Cipher/ARIA_256_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_CBC);
        case ID("Cryptofuzz/Cipher/ARIA_128_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_CTR);
        case ID("Cryptofuzz/Cipher/ARIA_192_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_CTR);
        case ID("Cryptofuzz/Cipher/ARIA_256_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_CTR);
        case ID("Cryptofuzz/Cipher/ARIA_128_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_GCM);
        case ID("Cryptofuzz/Cipher/ARIA_192_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_GCM);
        case ID("Cryptofuzz/Cipher/ARIA_256_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_GCM);
        default:
            return nullptr;
    }
}

mbedtls_md_type_t mbedTLS::to_mbedtls_md_type_t(const component::DigestType& digestType) const {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, mbedtls_md_type_t> LUT = {
        { ID("Cryptofuzz/Digest/SHA1"), MBEDTLS_MD_SHA1 },
        { ID("Cryptofuzz/Digest/SHA224"), MBEDTLS_MD_SHA224 },
        { ID("Cryptofuzz/Digest/SHA256"), MBEDTLS_MD_SHA256 },
        { ID("Cryptofuzz/Digest/SHA384"), MBEDTLS_MD_SHA384 },
        { ID("Cryptofuzz/Digest/SHA512"), MBEDTLS_MD_SHA512 },
        { ID("Cryptofuzz/Digest/MD2"), MBEDTLS_MD_MD2 },
        { ID("Cryptofuzz/Digest/MD4"), MBEDTLS_MD_MD4 },
        { ID("Cryptofuzz/Digest/MD5"), MBEDTLS_MD_MD5 },
        { ID("Cryptofuzz/Digest/RIPEMD160"), MBEDTLS_MD_RIPEMD160 },
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        return MBEDTLS_MD_NONE;
    }

    return LUT.at(digestType.Get());
}

std::optional<component::Ciphertext> mbedTLS::OpDigest(operation::Digest& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_md_info_t const* md_info = nullptr;
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md_type = to_mbedtls_md_type_t(op.digestType), MBEDTLS_MD_NONE);
        CF_CHECK_NE(md_info = mbedtls_md_info_from_type(md_type), nullptr);
        CF_CHECK_EQ(mbedtls_md_setup(&md_ctx, md_info, 0), 0 );
        CF_CHECK_EQ(mbedtls_md_starts(&md_ctx), 0);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(mbedtls_md_update(&md_ctx, part.first, part.second), 0);
    }

    /* Finalize */
    {
        unsigned char md[mbedtls_md_get_size(md_info)];
        CF_CHECK_EQ(mbedtls_md_finish(&md_ctx, md), 0);

        ret = component::Digest(md, mbedtls_md_get_size(md_info));
    }

end:
    mbedtls_md_free(&md_ctx);

    return ret;
}

std::optional<component::MAC> mbedTLS::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_md_info_t const* md_info = nullptr;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);


    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md_type = to_mbedtls_md_type_t(op.digestType), MBEDTLS_MD_NONE);
        CF_CHECK_NE(md_info = mbedtls_md_info_from_type(md_type), nullptr);
        CF_CHECK_EQ(mbedtls_md_setup(&md_ctx, md_info, 1), 0 );
        CF_CHECK_EQ(mbedtls_md_hmac_starts(&md_ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(mbedtls_md_hmac_update(&md_ctx, part.first, part.second), 0);
    }

    /* Finalize */
    {
        uint8_t out[MBEDTLS_MD_MAX_SIZE];
        CF_CHECK_EQ(mbedtls_md_hmac_finish(&md_ctx, out), 0);

        ret = component::MAC(out, mbedtls_md_get_size(md_info));
    }

end:
    mbedtls_md_free(&md_ctx);

    return ret;
}

std::optional<component::MAC> mbedTLS::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;

    const mbedtls_cipher_info_t *cipher_info = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(cipher_info = to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);
    }

    {
        uint8_t out[cipher_info->block_size];
        CF_CHECK_EQ(mbedtls_cipher_cmac(cipher_info, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, op.cleartext.GetPtr(), op.cleartext.GetSize(), out), 0);

        ret = component::MAC(out, cipher_info->block_size);
    }

end:

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
