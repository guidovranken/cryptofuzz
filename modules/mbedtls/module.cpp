#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/aria.h>
#include <mbedtls/camellia.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/pkcs12.h>
#include <mbedtls/platform.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

namespace mbedTLS_detail {
#if defined(CRYPTOFUZZ_MBEDTLS_ALLOCATION_FAILURES)
    Datasource* ds;
#endif

    inline void SetGlobalDs(Datasource* ds) {
#if defined(CRYPTOFUZZ_MBEDTLS_ALLOCATION_FAILURES)
        mbedTLS_detail::ds = ds;
#else
        (void)ds;
#endif
    }

    inline void UnsetGlobalDs(void) {
#if defined(CRYPTOFUZZ_MBEDTLS_ALLOCATION_FAILURES)
        mbedTLS_detail::ds = nullptr;
#endif
    }

    inline bool AllocationFailure(void) {
#if defined(CRYPTOFUZZ_MBEDTLS_ALLOCATION_FAILURES)
        bool fail = false;
        if ( ds == nullptr ) {
            return fail;
        }
        try {
            fail = ds->Get<bool>();
        } catch ( ... ) { }

        return fail;
#else
        return false;
#endif
    }
}

static void* mbedTLS_custom_calloc(size_t A, size_t B) {
    if ( mbedTLS_detail::AllocationFailure() == true ) {
        return nullptr;
    }

    /* TODO detect overflows */
    const size_t size = A*B;
    void* p = util::malloc(size);
    if ( size ) {
        memset(p, 0x00, size);
    }
    return p;
}

static void mbedTLS_custom_free(void* ptr) {
    util::free(ptr);
}

mbedTLS::mbedTLS(void) :
    Module("mbed TLS") {

    if ( mbedtls_platform_set_calloc_free(mbedTLS_custom_calloc, mbedTLS_custom_free) != 0 ) {
        abort();
    }
}

namespace mbedTLS_detail {
    const mbedtls_cipher_info_t* to_mbedtls_cipher_info_t(const component::SymmetricCipherType cipherType) {
        using fuzzing::datasource::ID;

        static const std::map<uint64_t, mbedtls_cipher_type_t> LUT = {
            { CF_CIPHER("AES_128_ECB"), MBEDTLS_CIPHER_AES_128_ECB  },
            { CF_CIPHER("AES_192_ECB"), MBEDTLS_CIPHER_AES_192_ECB  },
            { CF_CIPHER("AES_256_ECB"), MBEDTLS_CIPHER_AES_256_ECB  },
            { CF_CIPHER("AES_128_CBC"), MBEDTLS_CIPHER_AES_128_CBC  },
            { CF_CIPHER("AES_192_CBC"), MBEDTLS_CIPHER_AES_192_CBC  },
            { CF_CIPHER("AES_256_CBC"), MBEDTLS_CIPHER_AES_256_CBC  },
            { CF_CIPHER("AES_128_CFB128"), MBEDTLS_CIPHER_AES_128_CFB128  },
            { CF_CIPHER("AES_192_CFB128"), MBEDTLS_CIPHER_AES_192_CFB128  },
            { CF_CIPHER("AES_256_CFB128"), MBEDTLS_CIPHER_AES_256_CFB128  },
            { CF_CIPHER("AES_128_CTR"), MBEDTLS_CIPHER_AES_128_CTR  },
            { CF_CIPHER("AES_192_CTR"), MBEDTLS_CIPHER_AES_192_CTR  },
            { CF_CIPHER("AES_256_CTR"), MBEDTLS_CIPHER_AES_256_CTR  },
            { CF_CIPHER("AES_128_GCM"), MBEDTLS_CIPHER_AES_128_GCM  },
            { CF_CIPHER("AES_192_GCM"), MBEDTLS_CIPHER_AES_192_GCM  },
            { CF_CIPHER("AES_256_GCM"), MBEDTLS_CIPHER_AES_256_GCM  },
            { CF_CIPHER("CAMELLIA_128_ECB"), MBEDTLS_CIPHER_CAMELLIA_128_ECB  },
            { CF_CIPHER("CAMELLIA_192_ECB"), MBEDTLS_CIPHER_CAMELLIA_192_ECB  },
            { CF_CIPHER("CAMELLIA_256_ECB"), MBEDTLS_CIPHER_CAMELLIA_256_ECB  },
            { CF_CIPHER("CAMELLIA_128_CBC"), MBEDTLS_CIPHER_CAMELLIA_128_CBC  },
            { CF_CIPHER("CAMELLIA_192_CBC"), MBEDTLS_CIPHER_CAMELLIA_192_CBC  },
            { CF_CIPHER("CAMELLIA_256_CBC"), MBEDTLS_CIPHER_CAMELLIA_256_CBC  },
            { CF_CIPHER("CAMELLIA_128_CFB128"), MBEDTLS_CIPHER_CAMELLIA_128_CFB128  },
            { CF_CIPHER("CAMELLIA_192_CFB128"), MBEDTLS_CIPHER_CAMELLIA_192_CFB128  },
            { CF_CIPHER("CAMELLIA_256_CFB128"), MBEDTLS_CIPHER_CAMELLIA_256_CFB128  },
            { CF_CIPHER("CAMELLIA_128_CTR"), MBEDTLS_CIPHER_CAMELLIA_128_CTR  },
            { CF_CIPHER("CAMELLIA_192_CTR"), MBEDTLS_CIPHER_CAMELLIA_192_CTR  },
            { CF_CIPHER("CAMELLIA_256_CTR"), MBEDTLS_CIPHER_CAMELLIA_256_CTR  },
            { CF_CIPHER("CAMELLIA_128_GCM"), MBEDTLS_CIPHER_CAMELLIA_128_GCM  },
            { CF_CIPHER("CAMELLIA_192_GCM"), MBEDTLS_CIPHER_CAMELLIA_192_GCM  },
            { CF_CIPHER("CAMELLIA_256_GCM"), MBEDTLS_CIPHER_CAMELLIA_256_GCM  },
            { CF_CIPHER("DES_ECB"), MBEDTLS_CIPHER_DES_ECB  },
            { CF_CIPHER("DES_CBC"), MBEDTLS_CIPHER_DES_CBC  },
            { CF_CIPHER("DES_EDE_ECB"), MBEDTLS_CIPHER_DES_EDE_ECB  },
            { CF_CIPHER("DES_EDE_CBC"), MBEDTLS_CIPHER_DES_EDE_CBC  },
            { CF_CIPHER("DES_EDE3_ECB"), MBEDTLS_CIPHER_DES_EDE3_ECB  },
            { CF_CIPHER("DES_EDE3_CBC"), MBEDTLS_CIPHER_DES_EDE3_CBC  },
            { CF_CIPHER("BLOWFISH_ECB"), MBEDTLS_CIPHER_BLOWFISH_ECB  },
            { CF_CIPHER("BLOWFISH_CBC"), MBEDTLS_CIPHER_BLOWFISH_CBC  },
            { CF_CIPHER("BLOWFISH_CFB64"), MBEDTLS_CIPHER_BLOWFISH_CFB64  },
            { CF_CIPHER("BLOWFISH_CTR"), MBEDTLS_CIPHER_BLOWFISH_CTR  },
            { CF_CIPHER("RC4"), MBEDTLS_CIPHER_ARC4_128  },
            { CF_CIPHER("AES_128_CCM"), MBEDTLS_CIPHER_AES_128_CCM  },
            { CF_CIPHER("AES_192_CCM"), MBEDTLS_CIPHER_AES_192_CCM  },
            { CF_CIPHER("AES_256_CCM"), MBEDTLS_CIPHER_AES_256_CCM  },
            { CF_CIPHER("CAMELLIA_128_CCM"), MBEDTLS_CIPHER_CAMELLIA_128_CCM  },
            { CF_CIPHER("CAMELLIA_192_CCM"), MBEDTLS_CIPHER_CAMELLIA_192_CCM  },
            { CF_CIPHER("CAMELLIA_256_CCM"), MBEDTLS_CIPHER_CAMELLIA_256_CCM  },
            { CF_CIPHER("ARIA_128_ECB"), MBEDTLS_CIPHER_ARIA_128_ECB  },
            { CF_CIPHER("ARIA_192_ECB"), MBEDTLS_CIPHER_ARIA_192_ECB  },
            { CF_CIPHER("ARIA_256_ECB"), MBEDTLS_CIPHER_ARIA_256_ECB  },
            { CF_CIPHER("ARIA_128_CBC"), MBEDTLS_CIPHER_ARIA_128_CBC  },
            { CF_CIPHER("ARIA_192_CBC"), MBEDTLS_CIPHER_ARIA_192_CBC  },
            { CF_CIPHER("ARIA_256_CBC"), MBEDTLS_CIPHER_ARIA_256_CBC  },
            { CF_CIPHER("ARIA_128_CFB128"), MBEDTLS_CIPHER_ARIA_128_CFB128  },
            { CF_CIPHER("ARIA_192_CFB128"), MBEDTLS_CIPHER_ARIA_192_CFB128  },
            { CF_CIPHER("ARIA_256_CFB128"), MBEDTLS_CIPHER_ARIA_256_CFB128  },
            { CF_CIPHER("ARIA_128_CTR"), MBEDTLS_CIPHER_ARIA_128_CTR  },
            { CF_CIPHER("ARIA_192_CTR"), MBEDTLS_CIPHER_ARIA_192_CTR  },
            { CF_CIPHER("ARIA_256_CTR"), MBEDTLS_CIPHER_ARIA_256_CTR  },
            { CF_CIPHER("ARIA_128_GCM"), MBEDTLS_CIPHER_ARIA_128_GCM  },
            { CF_CIPHER("ARIA_192_GCM"), MBEDTLS_CIPHER_ARIA_192_GCM  },
            { CF_CIPHER("ARIA_256_GCM"), MBEDTLS_CIPHER_ARIA_256_GCM  },
            { CF_CIPHER("ARIA_128_CCM"), MBEDTLS_CIPHER_ARIA_128_CCM  },
            { CF_CIPHER("ARIA_192_CCM"), MBEDTLS_CIPHER_ARIA_192_CCM  },
            { CF_CIPHER("ARIA_256_CCM"), MBEDTLS_CIPHER_ARIA_256_CCM  },
            { CF_CIPHER("AES_128_OFB"), MBEDTLS_CIPHER_AES_128_OFB  },
            { CF_CIPHER("AES_192_OFB"), MBEDTLS_CIPHER_AES_192_OFB  },
            { CF_CIPHER("AES_256_OFB"), MBEDTLS_CIPHER_AES_256_OFB  },
            { CF_CIPHER("AES_128_XTS"), MBEDTLS_CIPHER_AES_128_XTS  },
            { CF_CIPHER("AES_256_XTS"), MBEDTLS_CIPHER_AES_256_XTS  },
            { CF_CIPHER("CHACHA20"), MBEDTLS_CIPHER_CHACHA20  },
            { CF_CIPHER("CHACHA20_POLY1305"), MBEDTLS_CIPHER_CHACHA20_POLY1305  },
            { CF_CIPHER("AES_128_WRAP"), MBEDTLS_CIPHER_AES_128_KW  },
            { CF_CIPHER("AES_128_WRAP_PAD"), MBEDTLS_CIPHER_AES_128_KWP  },
            { CF_CIPHER("AES_192_WRAP"), MBEDTLS_CIPHER_AES_192_KW  },
            { CF_CIPHER("AES_192_WRAP_PAD"), MBEDTLS_CIPHER_AES_192_KWP  },
            { CF_CIPHER("AES_256_WRAP"), MBEDTLS_CIPHER_AES_256_KW  },
            { CF_CIPHER("AES_256_WRAP_PAD"), MBEDTLS_CIPHER_AES_256_KWP },
        };

        if ( LUT.find(cipherType.Get()) == LUT.end() ) {
            return nullptr;
        }

        return mbedtls_cipher_info_from_type( LUT.at(cipherType.Get()) );
    }

    mbedtls_md_type_t to_mbedtls_md_type_t(const component::DigestType& digestType) {
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

}

std::optional<component::Digest> mbedTLS::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    util::Multipart parts;

    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_md_info_t const* md_info = nullptr;
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md_type = mbedTLS_detail::to_mbedtls_md_type_t(op.digestType), MBEDTLS_MD_NONE);
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

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::MAC> mbedTLS::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    util::Multipart parts;

    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_md_info_t const* md_info = nullptr;
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md_type = mbedTLS_detail::to_mbedtls_md_type_t(op.digestType), MBEDTLS_MD_NONE);
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

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::MAC> mbedTLS::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    const mbedtls_cipher_info_t *cipher_info = nullptr;
    uint8_t* out = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);
        out = util::malloc(cipher_info->block_size);
    }

    {
        CF_CHECK_EQ(mbedtls_cipher_cmac(cipher_info, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, op.cleartext.GetPtr(), op.cleartext.GetSize(), out), 0);

        ret = component::MAC(out, cipher_info->block_size);
    }

end:

    util::free(out);

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

namespace mbedTLS_detail {
    std::optional<component::Ciphertext> encrypt_AEAD(operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;

        mbedtls_cipher_context_t cipher_ctx;
        const mbedtls_cipher_info_t *cipher_info = nullptr;
        bool ctxInited = false;

        if ( op.tagSize == std::nullopt ) {
            return ret;
        }
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        mbedTLS_detail::SetGlobalDs(&ds);

        uint8_t* out = util::malloc(op.ciphertextSize);
        uint8_t* tag = util::malloc(*op.tagSize);

        /* Initialize */
        {
            CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);
            mbedtls_cipher_init(&cipher_ctx);
            ctxInited = true;
            CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
            CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, MBEDTLS_ENCRYPT), 0);
            CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
            /* "The buffer for the output data [...] must be able to hold at least ilen Bytes." */
            CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
        }

        /* Process/finalize */
        {
            size_t olen;
            CF_CHECK_EQ(mbedtls_cipher_auth_encrypt(&cipher_ctx,
                        op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetPtr() : nullptr, op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        op.cleartext.GetPtr(), op.cleartext.GetSize(),
                        out, &olen,
                        tag, *op.tagSize), 0);

            ret = component::Ciphertext(Buffer(out, olen), Buffer(tag, *op.tagSize));
        }

end:
        util::free(out);
        util::free(tag);

        if ( ctxInited == true ) {
            mbedtls_cipher_free(&cipher_ctx);
        }

        mbedTLS_detail::UnsetGlobalDs();

        return ret;
    }
}

std::optional<component::Ciphertext> mbedTLS::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20_POLY1305") ) {
        if ( op.cipher.iv.GetSize() > 12 ) {
            /* Circumvent the CVE-2019-1543 check in tests.cpp */
            return std::nullopt;
        }
    }

    if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20") && op.cipher.iv.GetSize() != 12 ) {
        return std::nullopt;
    }

    if ( op.tagSize != std::nullopt || op.aad != std::nullopt ) {
        return mbedTLS_detail::encrypt_AEAD(op);
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    util::Multipart parts;

    mbedtls_cipher_context_t cipher_ctx;
    bool ctxInited = false;
    const mbedtls_cipher_info_t *cipher_info = nullptr;

    size_t out_size = op.ciphertextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);

        mbedtls_cipher_init(&cipher_ctx);
        ctxInited = true;

        CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
        CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, MBEDTLS_ENCRYPT), 0);
        CF_CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), 0);
        CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
        CF_CHECK_EQ(mbedtls_cipher_update_ad(&cipher_ctx, nullptr, 0), 0);

        if ( repository::IsXTS( op.cipher.cipherType.Get() ) ) {
            /* XTS input may not be chunked */

            parts = { { op.cleartext.GetPtr(), op.cleartext.GetSize()} };
        } else if ( repository::IsGCM( op.cipher.cipherType.Get() ) || repository::IsECB( op.cipher.cipherType.Get() ) ) {
            /* mbed TLS documentation:
             *
             * If the underlying cipher is used in GCM mode, all calls
             * to this function, except for the last one before
             * mbedtls_cipher_finish(), must have \p ilen as a
             * multiple of the block size of the cipher.
             */

            const size_t blockSize = mbedtls_cipher_get_block_size(&cipher_ctx);
            const size_t numBlocks = op.cleartext.GetSize() / blockSize;
            const size_t remainder = op.cleartext.GetSize() % blockSize;

            /* ECB can only process cleartexts which are a multiple of the block size. */
            if (repository::IsECB( op.cipher.cipherType.Get() ) && remainder ) {
                goto end;
            }

            size_t i = 0;
            for (i = 0; i < numBlocks; i++) {
                parts.push_back( {op.cleartext.GetPtr() + (i * blockSize), blockSize} );
            }

            /* Do not add a chunk of size 0 in ECB mode (this will cause decryption to
             * fail).
             */
            if ( !repository::IsECB( op.cipher.cipherType.Get() ) ) {
                parts.push_back( {op.cleartext.GetPtr() + (i * blockSize), remainder} );
            }
        } else {
            parts = util::ToParts(ds, op.cleartext);
        }


        /* mbed TLS documentation:
         *      "The buffer for the output data.
         *      This must be able to hold at least ilen + block_size."
         */
        CF_CHECK_GTE(out_size, op.cleartext.GetSize() + mbedtls_cipher_get_block_size(&cipher_ctx));
    }

    /* Process */
    for (const auto& part : parts) {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_update(&cipher_ctx, part.first, part.second, out + outIdx, &olen), 0);
        outIdx += olen;
        out_size -= olen;
    }

    /* Finalize */
    {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_finish(&cipher_ctx, out + outIdx, &olen), 0);
        outIdx += olen;
        out_size -= olen;

        ret = component::Ciphertext(Buffer(out, outIdx));
    }

end:
    util::free(out);

    if ( ctxInited == true ) {
        mbedtls_cipher_free(&cipher_ctx);
    }

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

namespace mbedTLS_detail {
    std::optional<component::Cleartext> decrypt_AEAD(operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        mbedTLS_detail::SetGlobalDs(&ds);

        mbedtls_cipher_context_t cipher_ctx;
        const mbedtls_cipher_info_t *cipher_info = nullptr;
        bool ctxInited = false;

        uint8_t* out = util::malloc(op.cleartextSize);

        /* Initialize */
        {
            CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);
            mbedtls_cipher_init(&cipher_ctx);
            ctxInited = true;
            CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
            CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, MBEDTLS_DECRYPT), 0);
            CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
            /* "The buffer for the output data [...] must be able to hold at least ilen Bytes." */
            CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        }


        /* Process/finalize */
        {
            size_t olen;
            CF_CHECK_EQ(mbedtls_cipher_auth_decrypt(&cipher_ctx,
                        op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetPtr() : nullptr, op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        op.ciphertext.GetPtr(), op.ciphertext.GetSize(),
                        out, &olen,
                        op.tag != std::nullopt ? op.tag->GetPtr() : nullptr, op.tag != std::nullopt ? op.tag->GetSize() : 0), 0);

            ret = component::Cleartext(Buffer(out, olen));
        }

end:
        util::free(out);

        if ( ctxInited == true ) {
            mbedtls_cipher_free(&cipher_ctx);
        }

        mbedTLS_detail::UnsetGlobalDs();

        return ret;
    }
}

std::optional<component::Cleartext> mbedTLS::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;

    if ( op.aad != std::nullopt || op.tag != std::nullopt ) {
        return mbedTLS_detail::decrypt_AEAD(op);
    }

    if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20") && op.cipher.iv.GetSize() != 12 ) {
        return std::nullopt;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    util::Multipart parts;

    mbedtls_cipher_context_t cipher_ctx;
    bool ctxInited = false;
    const mbedtls_cipher_info_t *cipher_info = nullptr;

    size_t out_size = op.cleartextSize;
    size_t outIdx = 0;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);

        mbedtls_cipher_init(&cipher_ctx);
        ctxInited = true;

        CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
        CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize() * 8, MBEDTLS_DECRYPT), 0);
        CF_CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize()), 0);
        CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
        CF_CHECK_EQ(mbedtls_cipher_update_ad(&cipher_ctx, nullptr, 0), 0);

        if ( repository::IsXTS( op.cipher.cipherType.Get() ) ) {
            /* XTS input may not be chunked */

            parts = { { op.ciphertext.GetPtr(), op.ciphertext.GetSize()} };
        } else if ( repository::IsGCM( op.cipher.cipherType.Get() ) || repository::IsECB( op.cipher.cipherType.Get() ) ) {
            /* mbed TLS documentation:
             *
             * If the underlying cipher is used in GCM mode, all calls
             * to this function, except for the last one before
             * mbedtls_cipher_finish(), must have ilen as a
             * multiple of the block size of the cipher.
             */

            /* Ciphertexts encrypted using ECB fail to decrypt if it is
             * not passed in chunks of 1 block size (even if the total size
             * of the ciphertext is a multiple of the blocksize).
             *
             * So if a cipher's block size is 8, then passing 16 bytes to
             * mbedtls_cipher_update will fail.
             *
             * Hence, follow the same procedure for ECB: divide the ciphertext
             * into chunks of 1 block size.
             */

            const size_t blockSize = mbedtls_cipher_get_block_size(&cipher_ctx);
            const size_t numBlocks = op.ciphertext.GetSize() / blockSize;
            const size_t remainder = op.ciphertext.GetSize() % blockSize;

            /* ECB can only process ciphertexts which are a multiple of the block size. */
            if (repository::IsECB( op.cipher.cipherType.Get() ) && remainder ) {
                goto end;
            }

            size_t i = 0;
            for (i = 0; i < numBlocks; i++) {
                parts.push_back( {op.ciphertext.GetPtr() + (i * blockSize), blockSize} );
            }

            /* Do not add a chunk of size 0 in ECB mode (this will cause decryption to
             * fail).
             */
            if ( !repository::IsECB( op.cipher.cipherType.Get() ) ) {
                parts.push_back( {op.ciphertext.GetPtr() + (i * blockSize), remainder} );
            }
        } else {
            parts = util::ToParts(ds, op.ciphertext);
        }

        /* mbed TLS documentation:
         *      "The buffer for the output data.
         *      This must be able to hold at least ilen + block_size."
         */
        CF_CHECK_GTE(out_size, op.ciphertext.GetSize() + mbedtls_cipher_get_block_size(&cipher_ctx));
    }

    /* Process */
    for (const auto& part : parts) {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_update(&cipher_ctx, part.first, part.second, out + outIdx, &olen), 0);
        outIdx += olen;
        out_size -= olen;
    }

    /* Finalize */
    {
        size_t olen;
        CF_CHECK_EQ(mbedtls_cipher_finish(&cipher_ctx, out + outIdx, &olen), 0);
        outIdx += olen;
        out_size -= olen;

        ret = component::Cleartext(out, outIdx);
    }

end:
    util::free(out);

    if ( ctxInited == true ) {
        mbedtls_cipher_free(&cipher_ctx);
    }

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> mbedTLS::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_md_info_t const* md_info = nullptr;
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_NE(md_type = mbedTLS_detail::to_mbedtls_md_type_t(op.digestType), MBEDTLS_MD_NONE);
    CF_CHECK_NE(md_info = mbedtls_md_info_from_type(md_type), nullptr);

    /* https://tls.mbed.org/api/hkdf_8h.html:
     *
     * "The length of the output keying material in bytes.
     * This must be less than or equal to 255 * md.size bytes."
     */
    CF_CHECK_LTE(op.keySize, 255 * mbedtls_md_get_size(md_info));
    CF_CHECK_EQ(
            mbedtls_hkdf(
                md_info,
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.password.GetPtr(),
                op.password.GetSize(),
                op.info.GetPtr(),
                op.info.GetSize(),
                out,
                op.keySize), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> mbedTLS::OpKDF_PBKDF(operation::KDF_PBKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    uint8_t* out = util::malloc(op.keySize);

    /* Initialize */
    {
        CF_CHECK_NE(md_type = mbedTLS_detail::to_mbedtls_md_type_t(op.digestType), MBEDTLS_MD_NONE);
        CF_CHECK_GT(op.password.GetSize(), 0);
        CF_CHECK_GT(op.salt.GetSize(), 0);
    }

    CF_CHECK_EQ(mbedtls_pkcs12_derivation(
                out,
                op.keySize,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                md_type,
                MBEDTLS_PKCS12_DERIVE_KEY,
                op.iterations), 0);

    ret = component::Key(out, op.keySize);
end:
    util::free(out);

    return ret;
}

std::optional<component::Key> mbedTLS::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;
    mbedtls_md_info_t const* md_info = nullptr;
    mbedtls_md_context_t md_ctx;
    uint8_t* out = util::malloc(op.keySize);

    /* Initialize */
    {
        mbedtls_md_init(&md_ctx);
        CF_CHECK_NE(md_type = mbedTLS_detail::to_mbedtls_md_type_t(op.digestType), MBEDTLS_MD_NONE);
        CF_CHECK_NE(md_info = mbedtls_md_info_from_type(md_type), nullptr);
        CF_CHECK_EQ(mbedtls_md_setup(&md_ctx, md_info, 1), 0 );
        CF_CHECK_EQ(mbedtls_md_starts(&md_ctx), 0);
    }

    CF_CHECK_EQ(mbedtls_pkcs5_pbkdf2_hmac(
                &md_ctx,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.iterations,
                op.keySize,
                out), 0);

    ret = component::Key(out, op.keySize);

end:
    mbedtls_md_free(&md_ctx);
    util::free(out);

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

namespace mbedTLS_detail {
    std::optional<uint16_t> toTLSID(const component::CurveType& curveType) {
        static const std::map<uint64_t, uint16_t> LUT = {
            { CF_ECC_CURVE("secp521r1"), 25 },
            { CF_ECC_CURVE("brainpool512r1"), 28 },
            { CF_ECC_CURVE("secp384r1"), 24 },
            { CF_ECC_CURVE("brainpool384r1"), 27 },
            { CF_ECC_CURVE("secp256r1"), 23 },
            { CF_ECC_CURVE("secp256k1"), 22 },
            { CF_ECC_CURVE("brainpool256r1"), 26 },
            { CF_ECC_CURVE("secp224r1"), 21 },
            { CF_ECC_CURVE("secp224k1"), 20 },
            { CF_ECC_CURVE("secp192r1"), 19 },
            { CF_ECC_CURVE("secp192k1"), 18 },
            { CF_ECC_CURVE("x25519"), 29 },
        };

        if ( LUT.find(curveType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(curveType.Get());
    }

    std::optional<std::string> MPIToString(const mbedtls_mpi* mpi) {
        std::optional<std::string> ret;
        char* output = NULL;
        size_t olen;

        CF_CHECK_EQ(mbedtls_mpi_write_string(mpi, 10, nullptr, 0, &olen), MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
        CF_CHECK_NE(output = (char*)malloc(olen), nullptr);
        CF_CHECK_EQ(mbedtls_mpi_write_string(mpi, 10, output, olen, &olen), 0);

        ret = std::string(output);

end:
        free(output);
        return ret;
    }
}

std::optional<component::ECC_PublicKey> mbedTLS::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_ecp_keypair keypair;
    const mbedtls_ecp_curve_info* curve_info = nullptr;

    /* noret */ mbedtls_ecp_keypair_init(&keypair);

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&keypair.grp, curve_info->grp_id), 0);

    /* Private key */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&keypair.d, 10, op.priv.ToString(ds).c_str()), 0);

    CF_CHECK_EQ(mbedtls_ecp_mul(&keypair.grp, &keypair.Q, &keypair.d, &keypair.grp.G, nullptr, nullptr), 0);

    {
        std::optional<std::string> pub_x_str;
        std::optional<std::string> pub_y_str;

        CF_CHECK_NE(pub_x_str = mbedTLS_detail::MPIToString(&keypair.Q.X), std::nullopt);
        CF_CHECK_NE(pub_y_str = mbedTLS_detail::MPIToString(&keypair.Q.Y), std::nullopt);

        ret = { *pub_x_str, *pub_y_str };
    }

end:
    /* noret */ mbedtls_ecp_keypair_free(&keypair);

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<bool> mbedTLS::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_ecdsa_context ctx;
    mbedtls_mpi sig_r, sig_s;
    const mbedtls_ecp_curve_info* curve_info = nullptr;

    /* noret */ mbedtls_ecdsa_init(&ctx);
    /* noret */ mbedtls_mpi_init(&sig_r);
    /* noret */ mbedtls_mpi_init(&sig_s);

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&ctx.grp, curve_info->grp_id), 0);

    /* Pubkey */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&ctx.Q.X, 10, op.pub.first.ToString(ds).c_str()), 0);
    CF_CHECK_EQ(mbedtls_mpi_read_string(&ctx.Q.Y, 10, op.pub.second.ToString(ds).c_str()), 0);
    CF_CHECK_EQ(mbedtls_mpi_lset(&ctx.Q.Z, 1), 0);

    /* Signature */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&sig_s, 10, op.signature.first.ToString(ds).c_str()), 0);
    CF_CHECK_EQ(mbedtls_mpi_read_string(&sig_r, 10, op.signature.second.ToString(ds).c_str()), 0);

    {
        const auto verifyRes = mbedtls_ecdsa_verify(&ctx.grp, op.cleartext.GetPtr(), op.cleartext.GetSize(), &ctx.Q, &sig_r, &sig_s);
        if ( verifyRes == 0 ) {
            ret = true;
        } else if ( verifyRes == MBEDTLS_ERR_ECP_VERIFY_FAILED ) {
            ret = false;
        }
    }

end:
    /* noret */ mbedtls_ecdsa_free(&ctx);
    /* noret */ mbedtls_mpi_free(&sig_r);
    /* noret */ mbedtls_mpi_free(&sig_s);

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Bignum> mbedTLS::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);
    std::unique_ptr<mbedTLS_bignum::Operation> opRunner = nullptr;

    std::vector<mbedTLS_bignum::Bignum> bn{
        mbedTLS_bignum::Bignum(),
        mbedTLS_bignum::Bignum(),
        mbedTLS_bignum::Bignum(),
        mbedTLS_bignum::Bignum()
    };
    mbedTLS_bignum::Bignum res;

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn[0].Set(op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn[1].Set(op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn[2].Set(op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn[3].Set(op.bn3.ToString(ds)), true);


    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::Div>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<mbedTLS_bignum::ExpMod>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::Sqr>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::GCD>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::Cmp>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::Abs>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::Neg>();
            break;
        case    CF_CALCOP("RShift(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::RShift>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::LShift1>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::IsNeg>();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::IsEq>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsOne(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::IsOne>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<mbedTLS_bignum::MulMod>();
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<mbedTLS_bignum::AddMod>();
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<mbedTLS_bignum::SubMod>();
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::SqrMod>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::Bit>();
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::CmpAbs>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::SetBit>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::ClearBit>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<mbedTLS_bignum::Mod>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);

    ret = res.ToComponentBignum();

end:

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
