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
#include <mbedtls/sha256.h>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

namespace mbedTLS_detail {
    Datasource* ds;

    inline void SetGlobalDs(Datasource* ds) {
        mbedTLS_detail::ds = ds;
    }

    inline void UnsetGlobalDs(void) {
        mbedTLS_detail::ds = nullptr;
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
    int RNG(void* arg, unsigned char* out, size_t size) {
        (void)arg;

        CF_ASSERT(ds != nullptr, "global DS is NULL");

        if ( size == 0 ) {
            return 0;
        }

        try {
            const auto data = ds->GetData(0, size, size);
            CF_ASSERT(data.size() == (size_t)size, "Unexpected data size");
            memcpy(out, data.data(), size);

            return 0;
        } catch ( ... ) { }

        return -1;
    }

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
        CF_CHECK_EQ(mbedtls_md_hmac_starts(&md_ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
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

    mbedtls_cipher_context_t cipher_ctx;
    bool ctxInited = false;
    const mbedtls_cipher_info_t *cipher_info = nullptr;
    uint8_t* out = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);
        mbedtls_cipher_init(&cipher_ctx);
        ctxInited = true;
        out = util::malloc(mbedtls_cipher_get_block_size(&cipher_ctx));
    }

    {
        CF_CHECK_EQ(mbedtls_cipher_cmac(cipher_info, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize() * 8, op.cleartext.GetPtr(&ds), op.cleartext.GetSize(), out), 0);

        ret = component::MAC(out, mbedtls_cipher_get_block_size(&cipher_ctx));
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

        /* Initialize */
        {
            CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);
            mbedtls_cipher_init(&cipher_ctx);
            ctxInited = true;
            CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
            CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize() * 8, MBEDTLS_ENCRYPT), 0);
            CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
            /* "The buffer for the output data [...] must be able to hold at least ilen Bytes." */
            CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
        }

        /* Process/finalize */
        {
            size_t olen;
            CF_CHECK_EQ(mbedtls_cipher_auth_encrypt_ext(&cipher_ctx,
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetPtr(&ds) : nullptr, op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                        out, op.ciphertextSize,
                        &olen, *op.tagSize), 0);

            if ( !repository::IsWRAP(op.cipher.cipherType.Get()) ) {
                CF_ASSERT(olen == op.cleartext.GetSize() + *op.tagSize, "mbedtls_cipher_auth_encrypt_ext: Invalid outlen");
                ret = component::Ciphertext(
                        Buffer(out, op.cleartext.GetSize()),
                        Buffer(out + op.cleartext.GetSize(), *op.tagSize));
            } else {
                ret = component::Ciphertext(Buffer(out, olen));
            }
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
        CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize() * 8, MBEDTLS_ENCRYPT), 0);
        CF_CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx, op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);
        CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
        CF_CHECK_EQ(mbedtls_cipher_update_ad(&cipher_ctx, nullptr, 0), 0);

        if ( repository::IsXTS( op.cipher.cipherType.Get() ) ) {
            /* XTS input may not be chunked */

            parts = { { op.cleartext.GetPtr(&ds), op.cleartext.GetSize()} };
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
                parts.push_back( {op.cleartext.GetPtr(&ds) + (i * blockSize), blockSize} );
            }

            /* Do not add a chunk of size 0 in ECB mode (this will cause decryption to
             * fail).
             */
            if ( !repository::IsECB( op.cipher.cipherType.Get() ) ) {
                parts.push_back( {op.cleartext.GetPtr(&ds) + (i * blockSize), remainder} );
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

        const size_t insize = op.ciphertext.GetSize() + (op.tag != std::nullopt ? op.tag->GetSize() : 0);
        uint8_t* in = util::malloc(insize);
        uint8_t* out = util::malloc(op.cleartextSize);

        /* Initialize */
        {
            CF_CHECK_NE(cipher_info = mbedTLS_detail::to_mbedtls_cipher_info_t(op.cipher.cipherType), nullptr);
            mbedtls_cipher_init(&cipher_ctx);
            ctxInited = true;
            CF_CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
            CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize() * 8, MBEDTLS_DECRYPT), 0);
            CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
            /* "The buffer for the output data [...] must be able to hold at least ilen Bytes." */
            CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        }

        memcpy(in, op.ciphertext.GetPtr(), op.ciphertext.GetSize());
        if ( op.tag != std::nullopt ) {
            memcpy(in + op.ciphertext.GetSize(), op.tag->GetPtr(&ds), op.tag->GetSize());
        }

        /* Process/finalize */
        {
            size_t olen;
            CF_CHECK_EQ(mbedtls_cipher_auth_decrypt_ext(&cipher_ctx,
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetPtr(&ds) : nullptr, op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        in, insize,
                        out, op.cleartextSize,
                        &olen, op.tag != std::nullopt ? op.tag->GetSize() : 0), 0);

            ret = component::Cleartext(Buffer(out, olen));
        }

end:
        util::free(in);
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
        CF_CHECK_EQ(mbedtls_cipher_setkey(&cipher_ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize() * 8, MBEDTLS_DECRYPT), 0);
        CF_CHECK_EQ(mbedtls_cipher_set_iv(&cipher_ctx, op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);
        CF_CHECK_EQ(mbedtls_cipher_reset(&cipher_ctx), 0);
        CF_CHECK_EQ(mbedtls_cipher_update_ad(&cipher_ctx, nullptr, 0), 0);

        if ( repository::IsXTS( op.cipher.cipherType.Get() ) ) {
            /* XTS input may not be chunked */

            parts = { { op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()} };
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
                parts.push_back( {op.ciphertext.GetPtr(&ds) + (i * blockSize), blockSize} );
            }

            /* Do not add a chunk of size 0 in ECB mode (this will cause decryption to
             * fail).
             */
            if ( !repository::IsECB( op.cipher.cipherType.Get() ) ) {
                parts.push_back( {op.ciphertext.GetPtr(&ds) + (i * blockSize), remainder} );
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
                op.salt.GetPtr(&ds),
                op.salt.GetSize(),
                op.password.GetPtr(&ds),
                op.password.GetSize(),
                op.info.GetPtr(&ds),
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
                op.password.GetPtr(&ds),
                op.password.GetSize(),
                op.salt.GetPtr(&ds),
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
                op.password.GetPtr(&ds),
                op.password.GetSize(),
                op.salt.GetPtr(&ds),
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
#if 0
            { CF_ECC_CURVE("x25519"), 29 },
#endif
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

    CF_NORET(mbedtls_ecp_keypair_init(&keypair));

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&keypair.grp, curve_info->grp_id), 0);

    /* Private key */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&keypair.d, 10, op.priv.ToString(ds).c_str()), 0);

    CF_CHECK_EQ(mbedtls_ecp_mul(&keypair.grp, &keypair.Q, &keypair.d, &keypair.grp.G, mbedTLS_detail::RNG, nullptr), 0);

    {
        std::optional<std::string> pub_x_str;
        std::optional<std::string> pub_y_str;

        CF_CHECK_NE(pub_x_str = mbedTLS_detail::MPIToString(&keypair.Q.X), std::nullopt);
        CF_CHECK_NE(pub_y_str = mbedTLS_detail::MPIToString(&keypair.Q.Y), std::nullopt);

        ret = { *pub_x_str, *pub_y_str };
    }

end:
    CF_NORET(mbedtls_ecp_keypair_free(&keypair));

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

namespace mbedTLS_detail {
    bool LoadPoint(
            fuzzing::datasource::Datasource& ds,
            const component::ECC_Point in,
            mbedtls_ecp_point& out,
            const component::CurveType curveType,
            const bool onlyAffine = false) {
        bool ret = false;

        bool projective = false;

        if ( onlyAffine == false ) {
            try {
                projective = ds.Get<bool>();
            } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
        }

        if ( projective == false ) {
            CF_CHECK_EQ(mbedtls_mpi_read_string(&out.X, 10, in.first.ToString(ds).c_str()), 0);
            CF_CHECK_EQ(mbedtls_mpi_read_string(&out.Y, 10, in.second.ToString(ds).c_str()), 0);
            CF_CHECK_EQ(mbedtls_mpi_lset(&out.Z, 1), 0);
        } else {
            const auto proj = util::ToRandomProjective(
                    ds,
                    in.first.ToTrimmedString(),
                    in.second.ToTrimmedString(),
                    curveType.Get());
            CF_CHECK_EQ(mbedtls_mpi_read_string(&out.X, 10, proj[0].c_str()), 0);
            CF_CHECK_EQ(mbedtls_mpi_read_string(&out.Y, 10, proj[1].c_str()), 0);
            CF_CHECK_EQ(mbedtls_mpi_read_string(&out.Z, 10, proj[2].c_str()), 0);
        }

        ret = true;
end:
        return ret;
    }
}

std::optional<bool> mbedTLS::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_ecp_group grp;
    mbedtls_ecp_point pub;
    const mbedtls_ecp_curve_info* curve_info = nullptr;

    CF_NORET(mbedtls_ecp_group_init(&grp));
    CF_NORET(mbedtls_ecp_point_init(&pub));

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&grp, curve_info->grp_id), 0);

    CF_CHECK_TRUE(mbedTLS_detail::LoadPoint(ds, op.pub, pub, op.curveType, true));

    ret = mbedtls_ecp_check_pubkey(&grp, &pub) == 0;

end:
    CF_NORET(mbedtls_ecp_group_free(&grp));
    CF_NORET(mbedtls_ecp_point_free(&pub));

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECC_Point> mbedTLS::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_ecp_group grp;
    mbedtls_ecp_point a;
    mbedtls_mpi b;
    mbedtls_ecp_point res;
    const mbedtls_ecp_curve_info* curve_info = nullptr;

    CF_NORET(mbedtls_ecp_group_init(&grp));
    CF_NORET(mbedtls_ecp_point_init(&a));
    CF_NORET(mbedtls_mpi_init(&b));
    CF_NORET(mbedtls_ecp_point_init(&res));

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&grp, curve_info->grp_id), 0);

    /* Load point */
    CF_CHECK_TRUE(mbedTLS_detail::LoadPoint(ds, op.a, a, op.curveType));

    /* Load scalar */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&b, 10, op.b.ToString(ds).c_str()), 0);

    /* res = point * scalar */
    CF_CHECK_EQ(mbedtls_ecp_mul(&grp, &res, &b, &a, mbedTLS_detail::RNG, nullptr), 0);

    if ( mbedtls_mpi_cmp_int(&b, 0) == 0 ) {
        CF_ASSERT(
                mbedtls_ecp_check_pubkey(&grp, &res) == 0,
                "Point multiplication by 0 does not yield point at infinity");
    }

    if ( mbedtls_ecp_check_pubkey(&grp, &a) != 0 ) {
            CF_ASSERT(
                    mbedtls_ecp_check_pubkey(&grp, &res) != 0,
                    "Point multiplication of invalid point yields valid point");
    }

    {
        std::optional<std::string> x_str, y_str;

        CF_CHECK_NE(x_str = mbedTLS_detail::MPIToString(&res.X), std::nullopt);
        CF_CHECK_NE(y_str = mbedTLS_detail::MPIToString(&res.Y), std::nullopt);

        ret = { *x_str, *y_str };
    }
end:
    CF_NORET(mbedtls_ecp_group_free(&grp));
    CF_NORET(mbedtls_ecp_point_free(&a));
    CF_NORET(mbedtls_mpi_free(&b));
    CF_NORET(mbedtls_ecp_point_free(&res));

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECC_Point> mbedTLS::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_ecp_group grp;
    mbedtls_ecp_point a, b, res;
    mbedtls_mpi scalar;
    const mbedtls_ecp_curve_info* curve_info = nullptr;

    CF_NORET(mbedtls_ecp_group_init(&grp));
    CF_NORET(mbedtls_ecp_point_init(&a));
    CF_NORET(mbedtls_ecp_point_init(&b));
    CF_NORET(mbedtls_mpi_init(&scalar));
    CF_NORET(mbedtls_ecp_point_init(&res));

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&grp, curve_info->grp_id), 0);

    /* Load point a */
    CF_CHECK_TRUE(mbedTLS_detail::LoadPoint(ds, op.a, a, op.curveType));

    /* https://github.com/ARMmbed/mbedtls/issues/5376 */
    CF_CHECK_LT(mbedtls_mpi_cmp_mpi(&a.X, &grp.N), 0);
    CF_CHECK_LT(mbedtls_mpi_cmp_mpi(&a.Y, &grp.N), 0);

    /* Load point b */
    CF_CHECK_TRUE(mbedTLS_detail::LoadPoint(ds, op.b, b, op.curveType));

    /* https://github.com/ARMmbed/mbedtls/issues/5376 */
    CF_CHECK_LT(mbedtls_mpi_cmp_mpi(&b.X, &grp.N), 0);
    CF_CHECK_LT(mbedtls_mpi_cmp_mpi(&b.Y, &grp.N), 0);

    CF_CHECK_EQ(mbedtls_mpi_lset(&scalar, 1), 0);

    /* res = a + b */
    CF_CHECK_EQ(mbedtls_ecp_muladd(&grp, &res, &scalar, &b, &scalar, &a), 0);

    CF_CHECK_EQ(mbedtls_ecp_check_pubkey(&grp, &res), 0);
    CF_CHECK_EQ(mbedtls_ecp_check_pubkey(&grp, &a), 0);
    CF_CHECK_EQ(mbedtls_ecp_check_pubkey(&grp, &b), 0);

    {
        std::optional<std::string> x_str, y_str;

        CF_CHECK_NE(x_str = mbedTLS_detail::MPIToString(&res.X), std::nullopt);
        CF_CHECK_NE(y_str = mbedTLS_detail::MPIToString(&res.Y), std::nullopt);

        ret = { *x_str, *y_str };
    }
end:
    CF_NORET(mbedtls_ecp_group_free(&grp));
    CF_NORET(mbedtls_ecp_point_free(&a));
    CF_NORET(mbedtls_ecp_point_free(&b));
    CF_NORET(mbedtls_mpi_free(&scalar));
    CF_NORET(mbedtls_ecp_point_free(&res));

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECDSA_Signature> mbedTLS::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
        return std::nullopt;
    }

    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    const mbedtls_ecp_curve_info* curve_info = nullptr;
    mbedtls_ecp_keypair keypair;
    mbedtls_mpi sig_r, sig_s;

    CF_NORET(mbedtls_ecp_keypair_init(&keypair));
    CF_NORET(mbedtls_mpi_init(&sig_r));
    CF_NORET(mbedtls_mpi_init(&sig_s));

    CF_CHECK_EQ(op.UseRandomNonce(), true);

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&keypair.grp, curve_info->grp_id), 0);

    /* Private key */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&keypair.d, 10, op.priv.ToString(ds).c_str()), 0);

    {
        const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
        CF_CHECK_EQ(mbedtls_ecdsa_sign(&keypair.grp, &sig_r, &sig_s, &keypair.d, CT.GetPtr(&ds), CT.GetSize(), mbedTLS_detail::RNG, nullptr), 0);
    }

    CF_CHECK_EQ(mbedtls_ecp_mul(&keypair.grp, &keypair.Q, &keypair.d, &keypair.grp.G, mbedTLS_detail::RNG, nullptr), 0);

    CF_ASSERT(
            mbedtls_ecdsa_verify(&keypair.grp, op.cleartext.GetPtr(&ds), op.cleartext.GetSize(), &keypair.Q, &sig_r, &sig_s) == 0,
            "Cannot verify generated signature");

    {
        std::optional<std::string> sig_r_str, sig_s_str, pub_x_str, pub_y_str;

        CF_CHECK_NE(sig_r_str = mbedTLS_detail::MPIToString(&sig_r), std::nullopt);
        CF_CHECK_NE(sig_s_str  = mbedTLS_detail::MPIToString(&sig_s), std::nullopt);
        CF_CHECK_NE(pub_x_str = mbedTLS_detail::MPIToString(&keypair.Q.X), std::nullopt);
        CF_CHECK_NE(pub_y_str = mbedTLS_detail::MPIToString(&keypair.Q.Y), std::nullopt);

        ret = {{*sig_r_str, *sig_s_str}, {*pub_x_str, *pub_y_str}};
    }

end:
    CF_NORET(mbedtls_ecp_keypair_free(&keypair));

    mbedTLS_detail::UnsetGlobalDs();

    CF_NORET(mbedtls_mpi_free(&sig_r));
    CF_NORET(mbedtls_mpi_free(&sig_s));

    return ret;
}

std::optional<bool> mbedTLS::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    if ( !op.digestType.Is(CF_DIGEST("SHA256")) &&
         !op.digestType.Is(CF_DIGEST("NULL")) ) {
        return std::nullopt;
    }

    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);

    mbedtls_ecdsa_context ctx;
    mbedtls_mpi sig_r, sig_s;
    const mbedtls_ecp_curve_info* curve_info = nullptr;

    CF_NORET(mbedtls_ecdsa_init(&ctx));
    CF_NORET(mbedtls_mpi_init(&sig_r));
    CF_NORET(mbedtls_mpi_init(&sig_s));

    {
        std::optional<uint16_t> tls_id;
        CF_CHECK_NE(tls_id = mbedTLS_detail::toTLSID(op.curveType), std::nullopt);
        CF_CHECK_NE(curve_info = mbedtls_ecp_curve_info_from_tls_id(*tls_id), nullptr);
    }

    CF_CHECK_EQ(mbedtls_ecp_group_load(&ctx.grp, curve_info->grp_id), 0);

    /* Pubkey */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&ctx.Q.X, 10, op.signature.pub.first.ToString(ds).c_str()), 0);
    CF_CHECK_EQ(mbedtls_mpi_read_string(&ctx.Q.Y, 10, op.signature.pub.second.ToString(ds).c_str()), 0);
    CF_CHECK_EQ(mbedtls_mpi_lset(&ctx.Q.Z, 1), 0);

    if ( mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q) != 0 ) {
        ret = false;
        goto end;
    }

    /* Signature */
    CF_CHECK_EQ(mbedtls_mpi_read_string(&sig_r, 10, op.signature.signature.first.ToString(ds).c_str()), 0);
    CF_CHECK_EQ(mbedtls_mpi_read_string(&sig_s, 10, op.signature.signature.second.ToString(ds).c_str()), 0);

    {
        int verifyRes;

        switch ( op.digestType.Get() ) {
            case    CF_DIGEST("SHA256"):
                {
                    uint8_t CT[32];
                    CF_CHECK_EQ(mbedtls_sha256(op.cleartext.GetPtr(&ds), op.cleartext.GetSize(), CT, 0), 0);
                    verifyRes = mbedtls_ecdsa_verify(&ctx.grp, CT, sizeof(CT), &ctx.Q, &sig_r, &sig_s);
                }
                break;
            case    CF_DIGEST("NULL"):
                {
                    const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
                    verifyRes = mbedtls_ecdsa_verify(&ctx.grp, CT.GetPtr(&ds), CT.GetSize(), &ctx.Q, &sig_r, &sig_s);
                }
                break;
            default:
                CF_UNREACHABLE();
        }

        if ( verifyRes == 0 ) {
            ret = true;
        } else if ( verifyRes == MBEDTLS_ERR_ECP_VERIFY_FAILED ) {
            ret = false;
        }
    }

end:
    CF_NORET(mbedtls_ecdsa_free(&ctx));
    CF_NORET(mbedtls_mpi_free(&sig_r));
    CF_NORET(mbedtls_mpi_free(&sig_s));

    mbedTLS_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Bignum> mbedTLS::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    mbedTLS_detail::SetGlobalDs(&ds);
    std::unique_ptr<mbedTLS_bignum::Operation> opRunner = nullptr;

    mbedTLS_bignum::BignumCluster bn{ds,
        mbedTLS_bignum::Bignum(ds),
        mbedTLS_bignum::Bignum(ds),
        mbedTLS_bignum::Bignum(ds),
        mbedTLS_bignum::Bignum(ds)
    };
    mbedTLS_bignum::Bignum res(ds);

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);


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
            /* Too slow with larger values */
            CF_CHECK_LT(op.bn0.GetSize(), 1000);
            CF_CHECK_LT(op.bn1.GetSize(), 1000);
            CF_CHECK_LT(op.bn2.GetSize(), 1000);

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
        case    CF_CALCOP("Set(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::Set>();
            break;
        case    CF_CALCOP("NumLSZeroBits(A)"):
            opRunner = std::make_unique<mbedTLS_bignum::NumLSZeroBits>();
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
