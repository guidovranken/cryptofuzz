#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace module {

mbedTLS::mbedTLS(void) :
    Module("mbed TLS") { }

const mbedtls_cipher_info_t* mbedTLS::to_mbedtls_cipher_info_t(const component::SymmetricCipherType cipherType) const {
    using fuzzing::datasource::ID;

    switch ( cipherType.Get() ) {
        case CF_CIPHER("AES_128_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
        case CF_CIPHER("AES_192_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
        case CF_CIPHER("AES_256_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
        case CF_CIPHER("AES_128_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
        case CF_CIPHER("AES_192_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CBC);
        case CF_CIPHER("AES_256_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
        case CF_CIPHER("AES_128_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128);
        case CF_CIPHER("AES_192_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CFB128);
        case CF_CIPHER("AES_256_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CFB128);
        case CF_CIPHER("AES_128_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CTR);
        case CF_CIPHER("AES_192_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CTR);
        case CF_CIPHER("AES_256_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CTR);
        case CF_CIPHER("AES_128_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
        case CF_CIPHER("AES_192_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_GCM);
        case CF_CIPHER("AES_256_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
        case CF_CIPHER("CAMELLIA_128_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_ECB);
        case CF_CIPHER("CAMELLIA_192_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_ECB);
        case CF_CIPHER("CAMELLIA_256_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_ECB);
        case CF_CIPHER("CAMELLIA_128_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_CBC);
        case CF_CIPHER("CAMELLIA_192_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_CBC);
        case CF_CIPHER("CAMELLIA_256_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_CBC);
        case CF_CIPHER("CAMELLIA_128_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_CFB128);
        case CF_CIPHER("CAMELLIA_192_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_CFB128);
        case CF_CIPHER("CAMELLIA_256_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_CFB128);
        case CF_CIPHER("CAMELLIA_128_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_CTR);
        case CF_CIPHER("CAMELLIA_192_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_CTR);
        case CF_CIPHER("CAMELLIA_256_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_CTR);
        case CF_CIPHER("CAMELLIA_128_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_GCM);
        case CF_CIPHER("CAMELLIA_192_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_GCM);
        case CF_CIPHER("CAMELLIA_256_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_GCM);
        case CF_CIPHER("DES_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_ECB);
        case CF_CIPHER("DES_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_CBC);
        case CF_CIPHER("DES_EDE_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_EDE_ECB);
        case CF_CIPHER("DES_EDE_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_EDE_CBC);
        case CF_CIPHER("DES_EDE3_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_EDE3_ECB);
        case CF_CIPHER("DES_EDE3_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_EDE3_CBC);
        case CF_CIPHER("BLOWFISH_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_BLOWFISH_ECB);
        case CF_CIPHER("BLOWFISH_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_BLOWFISH_CBC);
        case CF_CIPHER("BLOWFISH_CFB64"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_BLOWFISH_CFB64);
        case CF_CIPHER("BLOWFISH_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_BLOWFISH_CTR);
        case CF_CIPHER("ARC4_128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARC4_128);
        case CF_CIPHER("AES_128_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CCM);
        case CF_CIPHER("AES_192_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_CCM);
        case CF_CIPHER("AES_256_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CCM);
        case CF_CIPHER("CAMELLIA_128_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_128_CCM);
        case CF_CIPHER("CAMELLIA_192_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_192_CCM);
        case CF_CIPHER("CAMELLIA_256_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CAMELLIA_256_CCM);
        case CF_CIPHER("ARIA_128_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_ECB);
        case CF_CIPHER("ARIA_192_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_ECB);
        case CF_CIPHER("ARIA_256_ECB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_ECB);
        case CF_CIPHER("ARIA_128_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_CBC);
        case CF_CIPHER("ARIA_192_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_CBC);
        case CF_CIPHER("ARIA_256_CBC"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_CBC);
        case CF_CIPHER("ARIA_128_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_CFB128);
        case CF_CIPHER("ARIA_192_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_CFB128);
        case CF_CIPHER("ARIA_256_CFB128"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_CFB128);
        case CF_CIPHER("ARIA_128_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_CTR);
        case CF_CIPHER("ARIA_192_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_CTR);
        case CF_CIPHER("ARIA_256_CTR"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_CTR);
        case CF_CIPHER("ARIA_128_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_GCM);
        case CF_CIPHER("ARIA_192_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_GCM);
        case CF_CIPHER("ARIA_256_GCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_GCM);
        case CF_CIPHER("ARIA_128_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_128_CCM);
        case CF_CIPHER("ARIA_192_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_192_CCM);
        case CF_CIPHER("ARIA_256_CCM"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_ARIA_256_CCM);
        case CF_CIPHER("AES_128_OFB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_OFB);
        case CF_CIPHER("AES_192_OFB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_OFB);
        case CF_CIPHER("AES_256_OFB"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_OFB);
        case CF_CIPHER("AES_128_XTS"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_XTS);
        case CF_CIPHER("AES_256_XTS"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_XTS);
        case CF_CIPHER("CHACHA20"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CHACHA20);
        case CF_CIPHER("CHACHA20_POLY1305"):
            return mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_CHACHA20_POLY1305);
        default:
            return nullptr;
    }
}

mbedtls_md_type_t mbedTLS::to_mbedtls_md_type_t(const component::DigestType& digestType) const {
    using fuzzing::datasource::ID;

    static const std::map<uint64_t, mbedtls_md_type_t> LUT = {
        { CF_DIGEST("SHA1"), MBEDTLS_MD_SHA1 },
        { CF_DIGEST("SHA224"), MBEDTLS_MD_SHA224 },
        { CF_DIGEST("SHA256"), MBEDTLS_MD_SHA256 },
        { CF_DIGEST("SHA384"), MBEDTLS_MD_SHA384 },
        { CF_DIGEST("SHA512"), MBEDTLS_MD_SHA512 },
        { CF_DIGEST("MD2"), MBEDTLS_MD_MD2 },
        { CF_DIGEST("MD4"), MBEDTLS_MD_MD4 },
        { CF_DIGEST("MD5"), MBEDTLS_MD_MD5 },
        { CF_DIGEST("RIPEMD160"), MBEDTLS_MD_RIPEMD160 },
    };

    if ( LUT.find(digestType.Get()) == LUT.end() ) {
        return MBEDTLS_MD_NONE;
    }

    return LUT.at(digestType.Get());
}

std::optional<component::Digest> mbedTLS::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
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

std::optional<component::Ciphertext> mbedTLS::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    /* Currently no support for AEAD tags and AAD */
    if ( op.aad != std::nullopt ) {
        return ret;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    mbedtls_cipher_context_t cipher_ctx;
    bool ctxInited = false;
    const mbedtls_cipher_info_t *cipher_info = nullptr;

    size_t out_size = op.ciphertextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        CF_CHECK_NE(cipher_info = to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);

        mbedtls_cipher_init(&cipher_ctx);
        ctxInited = true;
        CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
        CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, MBEDTLS_ENCRYPT), 0);
        CF_CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), 0);
        CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);

        /* mbed TLS documentation:
         *      "The buffer for the output data.
         *      This must be able to hold at least ilen + block_size."
         */
        CF_CHECK_GTE(out_size, op.cleartext.GetSize() + mbedtls_cipher_get_block_size(&cipher_ctx));
    }

    /* Process */
    for (const auto& part : parts) {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_update(&cipher_ctx, part.first, part.second, out, &olen), 0);
        outIdx += olen;
        out_size -= olen;
    }

    /* Finalize */
    {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_finish(&cipher_ctx, out, &olen), 0);
        outIdx += olen;
        out_size -= olen;

        ret = component::Ciphertext(Buffer(out, outIdx));
    }

end:
    util::free(out);

    if ( ctxInited == true ) {
        mbedtls_cipher_free(&cipher_ctx);
    }

    /* Too many differences with OpenSSL, so don't compare for now */
    return std::nullopt;

    return ret;
}

std::optional<component::Cleartext> mbedTLS::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;

    /* Currently no support for AEAD tags and AAD */
    if ( op.aad != std::nullopt || op.tag != std::nullopt ) {
        return ret;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    mbedtls_cipher_context_t cipher_ctx;
    bool ctxInited = false;
    const mbedtls_cipher_info_t *cipher_info = nullptr;

    size_t out_size = op.cleartextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        parts = util::ToParts(ds, op.ciphertext);
        CF_CHECK_NE(cipher_info = to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);

        mbedtls_cipher_init(&cipher_ctx);
        ctxInited = true;
        CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
        CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, MBEDTLS_DECRYPT), 0);
        CF_CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), 0);
        CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);

        /* mbed TLS documentation:
         *      "The buffer for the output data.
         *      This must be able to hold at least ilen + block_size."
         */
        CF_CHECK_GTE(out_size, op.ciphertext.GetSize() + mbedtls_cipher_get_block_size(&cipher_ctx));
    }

    /* Process */
    for (const auto& part : parts) {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_update(&cipher_ctx, part.first, part.second, out, &olen), 0);
        outIdx += olen;
        out_size -= olen;
    }

    /* Finalize */
    {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_finish(&cipher_ctx, out, &olen), 0);
        outIdx += olen;
        out_size -= olen;

        ret = component::Cleartext(out, outIdx);
    }

end:
    util::free(out);

    if ( ctxInited == true ) {
        mbedtls_cipher_free(&cipher_ctx);
    }

    /* Too many differences with OpenSSL, so don't compare for now */
    return std::nullopt;

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
