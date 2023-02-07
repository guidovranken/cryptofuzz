#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "bn_ops.h"
extern "C" {
#include <wolfssl/openssl/hmac.h>
}
#include "module_internal.h"

namespace cryptofuzz {
namespace module {

wolfCrypt_OpenSSL::wolfCrypt_OpenSSL(void) :
    Module("wolfCrypt-OpenSSL") {
}

namespace wolfCrypt_OpenSSL_detail {
    const EVP_MD* toEVPMD(const component::DigestType& digestType) {
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
#elif defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("MDC2"), EVP_mdc2() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
#if 0
            { CF_DIGEST("MDC2"), EVP_mdc2() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
            { CF_DIGEST("SHA3-224"), EVP_sha3_224() },
            { CF_DIGEST("SHA3-256"), EVP_sha3_256() },
            { CF_DIGEST("SHA3-384"), EVP_sha3_384() },
            { CF_DIGEST("SHA3-512"), EVP_sha3_512() },
#endif
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
}

std::optional<component::Digest> wolfCrypt_OpenSSL::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    CF_EVP_MD_CTX ctx(ds);
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        CF_CHECK_NE(md = wolfCrypt_OpenSSL_detail::toEVPMD(op.digestType), nullptr);
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

namespace wolfCrypt_OpenSSL_detail {
std::optional<component::MAC> OpHMAC_EVP(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    CF_EVP_MD_CTX ctx(ds);
    const EVP_MD* md = nullptr;
    EVP_PKEY *pkey = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md = wolfCrypt_OpenSSL_detail::toEVPMD(op.digestType), nullptr);
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

std::optional<component::MAC> OpHMAC_HMAC(operation::HMAC& op, Datasource& ds) {
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
}

std::optional<component::MAC> wolfCrypt_OpenSSL::OpHMAC(operation::HMAC& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
    if (    op.digestType.Get() == CF_DIGEST("SIPHASH64") ||
            op.digestType.Get() == CF_DIGEST("SIPHASH128") ) {
        /* Not HMAC but invoking SipHash here anyway due to convenience. */
        return OpenSSL_detail::SipHash(op);
    }
#endif

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( useEVP == true ) {
#if !defined(CRYPTOFUZZ_BORINGSSL)
        return wolfCrypt_OpenSSL_detail::OpHMAC_EVP(op, ds);
#else
        return wolfCrypt_OpenSSL_detail::OpHMAC_HMAC(op, ds);
#endif
    } else {
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        return wolfCrypt_OpenSSL_detail::OpHMAC_HMAC(op, ds);
#else
        return wolfCrypt_OpenSSL_detail::OpHMAC_EVP(op, ds);
#endif
    }

    return {};
}

namespace wolfCrypt_OpenSSL_detail {

const EVP_CIPHER* toEVPCIPHER(const component::SymmetricCipherType cipherType) {
    using fuzzing::datasource::ID;

    switch ( cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
            return EVP_aes_128_cbc();
        case CF_CIPHER("AES_128_CFB1"):
            return EVP_aes_128_cfb1();
        case CF_CIPHER("AES_128_CFB8"):
            return EVP_aes_128_cfb8();
        case CF_CIPHER("AES_128_CTR"):
            return EVP_aes_128_ctr();
        case CF_CIPHER("AES_128_ECB"):
            return EVP_aes_128_ecb();
        case CF_CIPHER("AES_128_GCM"):
            return EVP_aes_128_gcm();
        case CF_CIPHER("AES_128_OFB"):
            return EVP_aes_128_ofb();
        case CF_CIPHER("AES_128_XTS"):
            return EVP_aes_128_xts();
        case CF_CIPHER("AES_192_CBC"):
            return EVP_aes_192_cbc();
        case CF_CIPHER("AES_192_CFB1"):
            return EVP_aes_192_cfb1();
        case CF_CIPHER("AES_192_CFB8"):
            return EVP_aes_192_cfb8();
        case CF_CIPHER("AES_192_CTR"):
            return EVP_aes_192_ctr();
        case CF_CIPHER("AES_192_ECB"):
            return EVP_aes_192_ecb();
        case CF_CIPHER("AES_192_GCM"):
            return EVP_aes_192_gcm();
        case CF_CIPHER("AES_192_OFB"):
            return EVP_aes_192_ofb();
        case CF_CIPHER("AES_256_CBC"):
            return EVP_aes_256_cbc();
        case CF_CIPHER("AES_256_CFB1"):
            return EVP_aes_256_cfb1();
        case CF_CIPHER("AES_256_CFB8"):
            return EVP_aes_256_cfb8();
        case CF_CIPHER("AES_256_CTR"):
            return EVP_aes_256_ctr();
        case CF_CIPHER("AES_256_ECB"):
            return EVP_aes_256_ecb();
        case CF_CIPHER("AES_256_GCM"):
            return EVP_aes_256_gcm();
        case CF_CIPHER("AES_256_OFB"):
            return EVP_aes_256_ofb();
        case CF_CIPHER("AES_256_XTS"):
            return EVP_aes_256_xts();
        case CF_CIPHER("DES_CBC"):
            return EVP_des_cbc();
        case CF_CIPHER("DES_ECB"):
            return EVP_des_ecb();
        case CF_CIPHER("DES_EDE3_CBC"):
            return EVP_des_ede3_cbc();
        case CF_CIPHER("RC4"):
            return EVP_rc4();
        default:
            return nullptr;
    }
}

inline bool isAEAD(const EVP_CIPHER* ctx) {
    return (EVP_CIPHER_flags(ctx) & EVP_CIPH_GCM_MODE) == EVP_CIPH_GCM_MODE;
}

bool checkSetIVLength(const uint64_t cipherType, const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputIvLength) {
    bool ret = false;

    const size_t ivLength = EVP_CIPHER_iv_length(cipher);
    const bool ivLengthMismatch = ivLength != inputIvLength;

    return !ivLengthMismatch;
    if ( isAEAD(cipher) == false ) {
        /* Return true (success) if input IV length is expected IV length */
        return !ivLengthMismatch;
    }

    const bool isCCM = repository::IsCCM( cipherType );

    /* Only AEAD ciphers past this point */

    /* EVP_CIPHER_iv_length may return the wrong default IV length for CCM ciphers.
     * Eg. EVP_CIPHER_iv_length returns 12 for EVP_aes_128_ccm() even though the
     * IV length is actually.
     *
     * Hence, with CCM ciphers set the desired IV length always.
     */

    if ( isCCM || ivLengthMismatch ) {
        CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, inputIvLength, nullptr), 1);
    }

    ret = true;
end:

    return ret;
}

bool checkSetKeyLength(const EVP_CIPHER* cipher, EVP_CIPHER_CTX* ctx, const size_t inputKeyLength) {
    (void)ctx;

    bool ret = false;

    const size_t keyLength = EVP_CIPHER_key_length(cipher);
    if ( keyLength != inputKeyLength ) {
        return false;
        CF_CHECK_EQ(EVP_CIPHER_CTX_set_key_length(ctx, inputKeyLength), 1);
    }

    ret = true;

end:
    return ret;
}

std::optional<component::Ciphertext> OpSymmetricEncrypt_EVP(operation::SymmetricEncrypt& op, Datasource& ds) {
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
        CF_CHECK_NE(cipher = wolfCrypt_OpenSSL_detail::toEVPCIPHER(op.cipher.cipherType), nullptr);
        if ( op.tagSize != std::nullopt || op.aad != std::nullopt ) {
            /* Trying to treat non-AEAD with AEAD-specific features (tag, aad)
             * leads to all kinds of gnarly memory bugs in OpenSSL.
             * It is quite arguably misuse of the OpenSSL API, so don't do this.
             */
            CF_CHECK_EQ(isAEAD(cipher), true);
        }

        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), cipher, nullptr, nullptr, nullptr), 1);

        /* Must be a multiple of the block size of this cipher */
        //CF_CHECK_EQ(op.cleartext.GetSize() % EVP_CIPHER_block_size(cipher), 0);

        /* Convert cleartext to parts */
        partsCleartext = util::CipherInputTransform(ds, op.cipher.cipherType, out, out_size, op.cleartext.GetPtr(), op.cleartext.GetSize());

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
            /* Get tag.
             *
             * See comments around EVP_CTRL_AEAD_SET_TAG in OpSymmetricDecrypt_EVP for reasons
             * as to why this is disabled for LibreSSL.
             */
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx.GetPtr(), EVP_CTRL_AEAD_GET_TAG, *op.tagSize, outTag), 1);
            ret = component::Ciphertext(Buffer(out, outIdx), Buffer(outTag, *op.tagSize));
        } else {
            ret = component::Ciphertext(Buffer(out, outIdx));
        }
    }

end:

    util::free(out);
    util::free(outTag);

    return ret;
}

}

std::optional<component::Ciphertext> wolfCrypt_OpenSSL::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    return wolfCrypt_OpenSSL_detail::OpSymmetricEncrypt_EVP(op, ds);
}

namespace wolfCrypt_OpenSSL_detail {

std::optional<component::Cleartext> OpSymmetricDecrypt_EVP(operation::SymmetricDecrypt& op, Datasource& ds) {
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
        }
        CF_CHECK_EQ(EVP_DecryptInit_ex(ctx.GetPtr(), cipher, nullptr, nullptr, nullptr), 1);

        /* Must be a multiple of the block size of this cipher */
        //CF_CHECK_EQ(op.ciphertext.GetSize() % EVP_CIPHER_block_size(cipher), 0);

        /* Convert ciphertext to parts */
        //partsCiphertext = util::CipherInputTransform(ds, op.cipher.cipherType, out, out_size, op.ciphertext.GetPtr(), op.ciphertext.GetSize());
        partsCiphertext = { {op.ciphertext.GetPtr(), op.ciphertext.GetSize()} };

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

        if ( op.tag != std::nullopt ) {
            CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx.GetPtr(), EVP_CTRL_AEAD_SET_TAG, op.tag->GetSize(), (void*)op.tag->GetPtr()), 1);
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

}

std::optional<component::Cleartext> wolfCrypt_OpenSSL::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    return wolfCrypt_OpenSSL_detail::OpSymmetricDecrypt_EVP(op, ds);
}

std::optional<component::MAC> wolfCrypt_OpenSSL::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    CF_CMAC_CTX ctx(ds);
    const EVP_CIPHER* cipher = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(cipher = wolfCrypt_OpenSSL_detail::toEVPCIPHER(op.cipher.cipherType), nullptr);
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

std::optional<component::Key> wolfCrypt_OpenSSL::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    EVP_PKEY_CTX* pctx = nullptr;
    const EVP_MD* md = nullptr;

    size_t out_size = op.keySize;
    uint8_t* out = util::malloc(out_size);

    /* Initialize */
    {
        CF_CHECK_NE(md = wolfCrypt_OpenSSL_detail::toEVPMD(op.digestType), nullptr);
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
}

std::optional<component::Key> wolfCrypt_OpenSSL::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    const EVP_MD* md = nullptr;

    const size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    CF_CHECK_NE(md = wolfCrypt_OpenSSL_detail::toEVPMD(op.digestType), nullptr);
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
}

static std::optional<int> toCurveNID(const component::CurveType& curveType) {
    static const std::map<uint64_t, int> LUT = {
        { CF_ECC_CURVE("secp192r1"), NID_X9_62_prime192v1 },
        { CF_ECC_CURVE("x962_p192v2"), NID_X9_62_prime192v2 },
        { CF_ECC_CURVE("x962_p192v3"), NID_X9_62_prime192v3 },
        { CF_ECC_CURVE("x962_p239v1"), NID_X9_62_prime239v1 },
        { CF_ECC_CURVE("x962_p239v2"), NID_X9_62_prime239v2 },
        { CF_ECC_CURVE("x962_p239v3"), NID_X9_62_prime239v3 },
        { CF_ECC_CURVE("secp256r1"), NID_X9_62_prime256v1 },
        { CF_ECC_CURVE("brainpool160r1"), NID_brainpoolP160r1 },
        { CF_ECC_CURVE("brainpool192r1"), NID_brainpoolP192r1 },
        { CF_ECC_CURVE("brainpool224r1"), NID_brainpoolP224r1 },
        { CF_ECC_CURVE("brainpool256r1"), NID_brainpoolP256r1 },
        { CF_ECC_CURVE("brainpool320r1"), NID_brainpoolP320r1 },
        { CF_ECC_CURVE("brainpool384r1"), NID_brainpoolP384r1 },
        { CF_ECC_CURVE("brainpool512r1"), NID_brainpoolP512r1 },
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
    };

    if ( LUT.find(curveType.Get()) == LUT.end() ) {
        return std::nullopt;
    }

    return LUT.at(curveType.Get());
}

std::optional<bool> wolfCrypt_OpenSSL::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
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
    CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
    CF_CHECK_TRUE(pub->Set(op.pub.first, op.pub.second));

    /* Reject oversized pubkeys until it is fixed in OpenSSL
     * https://github.com/openssl/openssl/issues/17590
     */
#if 0
    {
        const auto order = cryptofuzz::repository::ECC_CurveToOrder(op.curveType.Get());
        CF_CHECK_NE(order, std::nullopt);
        CF_CHECK_TRUE(op.pub.first.IsLessThan(*order));
        CF_CHECK_TRUE(op.pub.second.IsLessThan(*order));
    }
#endif

    ret = EC_KEY_set_public_key(key.GetPtr(), pub->GetPtr()) == 1;
end:
    return ret;
}

std::optional<component::ECC_PublicKey> wolfCrypt_OpenSSL::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    char* pub_x_str = nullptr;
    char* pub_y_str = nullptr;

    try {
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
        CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
        CF_CHECK_EQ(EC_POINT_mul(group->GetPtr(), pub->GetPtr(), prv.GetPtr(), nullptr, nullptr, nullptr), 1);

        CF_CHECK_EQ(pub_x.New(), true);
        CF_CHECK_EQ(pub_y.New(), true);

        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), pub->GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);

        /* Convert bignum x/y to strings */
        CF_CHECK_NE(pub_x_str = BN_bn2dec(pub_x.GetPtr()), nullptr);
        CF_CHECK_NE(pub_y_str = BN_bn2dec(pub_y.GetPtr()), nullptr);

        /* Save bignum x/y */
        ret = { std::string(pub_x_str), std::string(pub_y_str) };
    } catch ( ... ) { }

end:
    OPENSSL_free(pub_x_str);
    OPENSSL_free(pub_y_str);

    return ret;
}

std::optional<component::ECC_Point> wolfCrypt_OpenSSL::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

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

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(b = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
    CF_CHECK_TRUE(b->Set(op.b.first, op.b.second));

    CF_CHECK_NE(res = std::make_unique<CF_EC_POINT>(ds, group), nullptr);

    CF_CHECK_NE(EC_POINT_add(group->GetPtr(), res->GetPtr(), a->GetPtr(), b->GetPtr(), nullptr), 0);

    {
        OpenSSL_bignum::Bignum x(ds);
        OpenSSL_bignum::Bignum y(ds);

        CF_CHECK_EQ(x.New(), true);
        CF_CHECK_EQ(y.New(), true);

        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), res->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);

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

std::optional<component::ECC_Point> wolfCrypt_OpenSSL::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

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

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(res = std::make_unique<CF_EC_POINT>(ds, group), nullptr);

    CF_CHECK_EQ(b.Set(op.b.ToString(ds)), true);

    CF_CHECK_NE(EC_POINT_mul(group->GetPtr(), res->GetPtr(), nullptr, a->GetPtr(), b.GetPtr(), nullptr), 0);

    if ( op.b.ToTrimmedString() == "0" ) {
        CF_ASSERT(
                EC_POINT_is_at_infinity(group->GetPtr(), res->GetPtr()) == 1,
                "Point multiplication by 0 does not yield point at infinity");
    }

    {
        OpenSSL_bignum::BN_CTX ctx(ds);

        if ( !EC_POINT_is_on_curve(group->GetPtr(), a->GetPtr(), ctx.GetPtr()) ) {
            CF_ASSERT(
                    EC_POINT_is_on_curve(group->GetPtr(), res->GetPtr(), ctx.GetPtr()) == 0,
                    "Point multiplication of invalid point yields valid point");
        }
    }

    ret = res->Get();

end:
    OPENSSL_free(x_str);
    OPENSSL_free(y_str);

    return ret;
}

std::optional<component::ECC_Point> wolfCrypt_OpenSSL::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
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

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(EC_POINT_invert(group->GetPtr(), a->GetPtr(), nullptr), 0);

    {
        OpenSSL_bignum::Bignum x(ds);
        OpenSSL_bignum::Bignum y(ds);

        CF_CHECK_EQ(x.New(), true);
        CF_CHECK_EQ(y.New(), true);

        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), a->GetPtr(), x.GetDestPtr(), y.GetDestPtr(), nullptr), 0);

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

std::optional<bool> wolfCrypt_OpenSSL::OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::shared_ptr<CF_EC_GROUP> group = nullptr;
    std::unique_ptr<CF_EC_POINT> a = nullptr, b = nullptr;

    {
        std::optional<int> curveNID;
        CF_CHECK_NE(curveNID = toCurveNID(op.curveType), std::nullopt);
        CF_CHECK_NE(group = std::make_shared<CF_EC_GROUP>(ds, *curveNID), nullptr);
        group->Lock();
        CF_CHECK_NE(group->GetPtr(), nullptr);
    }

    CF_CHECK_NE(a = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
    CF_CHECK_TRUE(a->Set(op.a.first, op.a.second));

    CF_CHECK_NE(b = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
    CF_CHECK_TRUE(b->Set(op.b.first, op.b.second));

    ret = EC_POINT_cmp(group->GetPtr(), a->GetPtr(), b->GetPtr(), nullptr) == 0;

end:

    return ret;
}

std::optional<bool> wolfCrypt_OpenSSL::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

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
            CF_CHECK_EQ(ECDSA_SIG_set0(signature, sig_r.GetDestPtr(false), sig_s.GetDestPtr(false)), 1);
            /* 'signature' now has ownership, and the BIGNUMs will be freed by ECDSA_SIG_free */
            sig_r.ReleaseOwnership();
            sig_s.ReleaseOwnership();

            /* Construct key */
            CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
            CF_CHECK_TRUE(pub->Set(op.signature.pub.first, op.signature.pub.second));
            CF_CHECK_EQ(EC_KEY_set_public_key(key.GetPtr(), pub->GetPtr()), 1);
        }

        /* Process */
        {
            int res;
            if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
                //const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
                const auto CT = op.cleartext;
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

    return ret;
}

std::optional<component::ECDSA_Signature> wolfCrypt_OpenSSL::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

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

        CF_CHECK_TRUE(op.UseRandomNonce());
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
        CF_CHECK_NE(pub = std::make_unique<CF_EC_POINT>(ds, group), nullptr);
        CF_CHECK_EQ(EC_POINT_mul(group->GetPtr(), pub->GetPtr(), prv.GetPtr(), nullptr, nullptr, nullptr), 1);

        CF_CHECK_EQ(pub_x.New(), true);
        CF_CHECK_EQ(pub_y.New(), true);

        CF_CHECK_NE(EC_POINT_get_affine_coordinates(group->GetPtr(), pub->GetPtr(), pub_x.GetDestPtr(), pub_y.GetDestPtr(), nullptr), 0);

        CF_CHECK_NE(pub_x_str = BN_bn2dec(pub_x.GetPtr()), nullptr);
        CF_CHECK_NE(pub_y_str = BN_bn2dec(pub_y.GetPtr()), nullptr);

        const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);

        CF_CHECK_NE(signature = ECDSA_do_sign(CT.GetPtr(), CT.GetSize(), key.GetPtr()), nullptr);

        /* noret */ ECDSA_SIG_get0(signature, &R, &S);
        CF_CHECK_NE(R, nullptr);
        CF_CHECK_NE(S, nullptr);

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

    return ret;
}

std::optional<component::Bignum> wolfCrypt_OpenSSL::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

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

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sub>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mul>();
            break;
#endif
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::ExpMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sqr>();
            break;
#endif
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::GCD>();
            break;
#endif
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::AddMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::SubMod>();
            break;
#endif
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::MulMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SqrMod>();
            break;
#endif
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Cmp>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Div>();
            break;
#endif
        case    CF_CALCOP("IsPrime(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsPrime>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sqrt>();
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
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Jacobi>();
            break;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
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
        case    CF_CALCOP("SqrtMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SqrtMod>();
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::LCM>();
            break;
#endif
        case    CF_CALCOP("Exp(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Exp>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Abs>();
            break;
#endif
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
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::CmpAbs>();
            break;
#endif
#if !defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
        case    CF_CALCOP("ModLShift(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::ModLShift>();
            break;
#endif
        case    CF_CALCOP("IsPow2(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsPow2>();
            break;
        case    CF_CALCOP("Mask(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mask>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn, ctx), true);

    ret = res.ToComponentBignum();

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
