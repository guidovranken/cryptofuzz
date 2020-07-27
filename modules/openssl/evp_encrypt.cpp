#include "evp_encrypt.h"

#include <cryptofuzz/repository.h>

namespace cryptofuzz {
namespace module {
namespace OpenSSL_detail {

SymmetricEncrypt_EVP::SymmetricEncrypt_EVP(
        operation::SymmetricEncrypt& op,
        fuzzing::datasource::Datasource& ds) :
    op(op),
    ds(ds),
    ctx(ds),
    cleartext(op.cleartext.Get())
{ }

/* Called after each EVP_CIPHER_CTX access.
 *
 * The extracted boolean decides whether to skip to the 'again'
 * label in SymmetricEncrypt_EVP::Run.
 *
 * This purpose of this is to detect if CTX reuse results
 * in any unwanted behavior, like reported in this issue:
 *
 * https://github.com/openssl/openssl/issues/12405
 */
void SymmetricEncrypt_EVP::triggerReinitialize(void) const {
    if ( ds.Get<bool>() == true ) {
        throw Reinitialize();
    }
}

bool SymmetricEncrypt_EVP::initialize_parts(void) {
    /* Convert cleartext to parts */
    partsCleartext = util::CipherInputTransform(ds, op.cipher.cipherType, out, outSize, cleartext.data(), cleartext.size());

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

    return true;
}

bool SymmetricEncrypt_EVP::initialize_EVP_1(void) {
    bool ret = false;

    if ( op.tagSize != std::nullopt || op.aad != std::nullopt ) {
        /* Trying to treat non-AEAD with AEAD-specific features (tag, aad)
         * leads to all kinds of gnarly memory bugs in OpenSSL.
         * It is quite arguably misuse of the OpenSSL API, so don't do this.
         */
        CF_CHECK_EQ(OpenSSL_detail::isAEAD(cipher, op.cipher.cipherType.Get()), true);
    }

    if ( repository::IsWRAP(op.cipher.cipherType.Get()) ) {
        /* noret */ EVP_CIPHER_CTX_set_flags(ctx.GetPtr(), EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        triggerReinitialize();
    }

    ret = true;

end:
    return ret;
}

bool SymmetricEncrypt_EVP::initialize_EVP_2(void) {
    bool ret = false;

    CF_CHECK_EQ(EVP_EncryptInit_ex(
                ctx.GetPtr(),
                ctxInitializedOnce == false ? cipher : nullptr,
                nullptr,
                nullptr,
                nullptr), 1);
    ctxInitializedOnce = true;
    triggerReinitialize();

    ret = true;

end:
    return ret;
}

bool SymmetricEncrypt_EVP::prepare_CCM(void) {
    bool ret = false;

    if ( repository::IsCCM(op.cipher.cipherType.Get()) == true ) {
        int len;
        CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), nullptr, &len, nullptr, cleartext.size()), 1);
        triggerReinitialize();
    }

    ret = true;

end:
    return ret;
}

bool SymmetricEncrypt_EVP::set_AAD(void) {
    bool ret = false;

    if ( op.aad != std::nullopt ) {
        for (const auto& part : partsAAD) {
            int len;
            CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), nullptr, &len, part.first, part.second), 1);
            triggerReinitialize();
        }
    }

    ret = true;

end:
    return ret;
}

bool SymmetricEncrypt_EVP::encrypt(void) {
    bool ret = false;

    for (const auto& part : partsCleartext) {
        /* "the amount of data written may be anything from zero bytes to (inl + cipher_block_size - 1)" */
        CF_CHECK_GTE(outSize, part.second + EVP_CIPHER_block_size(cipher) - 1);

        int len = -1;
        CF_CHECK_EQ(EVP_EncryptUpdate(ctx.GetPtr(), out + outIdx, &len, part.first, part.second), 1);
        triggerReinitialize();
        outIdx += len;
        outSize -= len;
    }

    ret = true;

end:
    return ret;
}
std::optional<component::Ciphertext> SymmetricEncrypt_EVP::finalize(void) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    int len = -1;

    CF_CHECK_GTE(outSize, static_cast<size_t>(EVP_CIPHER_block_size(cipher)));

    CF_CHECK_EQ(EVP_EncryptFinal_ex(ctx.GetPtr(), out + outIdx, &len), 1);
    triggerReinitialize();
    outIdx += len;

    if ( op.tagSize != std::nullopt ) {
#if !defined(CRYPTOFUZZ_LIBRESSL) && !defined(CRYPTOFUZZ_OPENSSL_102)
        /* Get tag.
         *
         * See comments around EVP_CTRL_AEAD_SET_TAG in OpSymmetricDecrypt_EVP for reasons
         * as to why this is disabled for LibreSSL.
         */
        CF_CHECK_EQ(EVP_CIPHER_CTX_ctrl(ctx.GetPtr(), EVP_CTRL_AEAD_GET_TAG, *op.tagSize, outTag), 1);
        triggerReinitialize();
        ret = component::Ciphertext(Buffer(out, outIdx), Buffer(outTag, *op.tagSize));
#endif
    } else {
        ret = component::Ciphertext(Buffer(out, outIdx));
    }

end:
    return ret;
}

bool SymmetricEncrypt_EVP::prepare_IV(void) {
    bool ret = false;

    if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20") ) {
        CF_CHECK_EQ(OpenSSL_detail::checkSetIVLength(op.cipher.cipherType.Get(), cipher, ctx.GetPtr(), op.cipher.iv.GetSize()), true);
        triggerReinitialize();
    } else {
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);
    }

    ret = true;

end:
    return ret;
}

bool SymmetricEncrypt_EVP::prepare_key(void) {
    bool ret = false;

    CF_CHECK_EQ(OpenSSL_detail::checkSetKeyLength(cipher, ctx.GetPtr(), op.cipher.key.GetSize()), true);
    triggerReinitialize();

    ret = true;

end:
    return ret;
}

bool SymmetricEncrypt_EVP::set_IV_key(void) {
    bool ret = false;

    if ( op.cipher.cipherType.Get() != CF_CIPHER("CHACHA20") ) {
        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr()), 1);
        triggerReinitialize();
    } else {
        /* Prepend the 32 bit counter (which is 0) to the iv */
        uint8_t cc20IV[16];
        memset(cc20IV, 0, 4);
        memcpy(cc20IV + 4, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
        CF_CHECK_EQ(EVP_EncryptInit_ex(ctx.GetPtr(), nullptr, nullptr, op.cipher.key.GetPtr(), cc20IV), 1);
        triggerReinitialize();
    }

    ret = true;

end:
    return ret;
}

bool SymmetricEncrypt_EVP::set_padding(void) {
    bool ret = false;

    if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
        CF_CHECK_EQ(EVP_CIPHER_CTX_set_padding(ctx.GetPtr(), 0), 1);
        triggerReinitialize();
    }

    ret = true;

end:
    return ret;
}

std::optional<component::Ciphertext> SymmetricEncrypt_EVP::Run(void) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    try {
        out = util::malloc(op.ciphertextSize);
        outSize = op.ciphertextSize;
        outTag = op.tagSize != std::nullopt ?
                    util::malloc(*op.tagSize) :
                    nullptr;

        CF_CHECK_NE(cipher = OpenSSL_detail::toEVPCIPHER(op.cipher.cipherType), nullptr);
again:
        CF_CHECK_EQ(initialize_parts(), true);

        try {
            ret = std::nullopt;
            outSize = op.ciphertextSize;
            outIdx = 0;

            CF_CHECK_EQ(initialize_EVP_1(), true);
            CF_CHECK_EQ(initialize_EVP_2(), true);

            CF_CHECK_EQ(prepare_IV(), true);
            CF_CHECK_EQ(prepare_key(), true);
            CF_CHECK_EQ(set_IV_key(), true);
            CF_CHECK_EQ(set_padding(), true);

            CF_CHECK_EQ(prepare_CCM(), true);
            CF_CHECK_EQ(set_AAD(), true);
            CF_CHECK_EQ(encrypt(), true);

            ret = finalize();
        } catch ( Reinitialize ) { goto again; }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

end:
    util::free(out);
    util::free(outTag);

    return ret;
}

} /* namespace OpenSSL_detail */
} /* namespace module */
} /* namespace cryptofuzz */
