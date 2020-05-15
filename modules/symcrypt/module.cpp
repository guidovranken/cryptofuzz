#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <symcrypt.h>

extern "C" {
    void SymCryptFatal(UINT32 fatalCode) {
        (void)fatalCode;

        abort();
    }
    void SymCryptInjectError( PBYTE pbData, SIZE_T cbData ) {
        (void)pbData;
        (void)cbData;
    }
}

namespace cryptofuzz {
namespace module {

SymCrypt::SymCrypt(void) :
    Module("SymCrypt") {
}

namespace SymCrypt_detail {
    const SYMCRYPT_HASH* to_SYMCRYPT_HASH(const component::DigestType& digestType) {
        switch ( digestType.Get() ) {
            case CF_DIGEST("MD2"):
                return SymCryptMd2Algorithm;
            case CF_DIGEST("MD4"):
                return SymCryptMd4Algorithm;
            case CF_DIGEST("MD5"):
                return SymCryptMd5Algorithm;
            case CF_DIGEST("SHA1"):
                return SymCryptSha1Algorithm;
            case CF_DIGEST("SHA256"):
                return SymCryptSha256Algorithm;
            case CF_DIGEST("SHA512"):
                return SymCryptSha512Algorithm;
        }

        return nullptr;
    }

    const SYMCRYPT_MAC* to_SYMCRYPT_MAC(const component::DigestType& digestType) {
        switch ( digestType.Get() ) {
            case CF_DIGEST("MD5"):
                return SymCryptHmacMd5Algorithm;
            case CF_DIGEST("SHA1"):
                return SymCryptHmacSha1Algorithm;
            case CF_DIGEST("SHA256"):
                return SymCryptHmacSha256Algorithm;
            case CF_DIGEST("SHA384"):
                return SymCryptHmacSha384Algorithm;
            case CF_DIGEST("SHA512"):
                return SymCryptHmacSha512Algorithm;
        }

        return nullptr;
    }

    const SYMCRYPT_BLOCKCIPHER* to_SYMCRYPT_BLOCKCIPHER(const component::SymmetricCipherType& cipherType) {
        switch ( cipherType.Get() ) {
            case CF_CIPHER("AES_128_ECB"):
            case CF_CIPHER("AES_192_ECB"):
            case CF_CIPHER("AES_256_ECB"):
            case CF_CIPHER("AES_128_CFB"):
            case CF_CIPHER("AES_192_CFB"):
            case CF_CIPHER("AES_256_CFB"):
            case CF_CIPHER("AES_128_CBC"):
            case CF_CIPHER("AES_192_CBC"):
            case CF_CIPHER("AES_256_CBC"):
                return SymCryptAesBlockCipher;
            case CF_CIPHER("RC2_ECB"):
            case CF_CIPHER("RC2_CFB"):
            case CF_CIPHER("RC2_CBC"):
                return SymCryptRc2BlockCipher;
            case CF_CIPHER("DESX_A_CBC"):
                return SymCryptDesxBlockCipher;
            case CF_CIPHER("DES_EDE3_ECB"):
            case CF_CIPHER("DES_EDE3_CFB"):
            case CF_CIPHER("DES_EDE3_CBC"):
                return SymCrypt3DesBlockCipher;
        }

        return nullptr;
    }
}

std::optional<component::Digest> SymCrypt::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;
    uint8_t* state = nullptr;
    const SYMCRYPT_HASH* hasher = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(hasher = SymCrypt_detail::to_SYMCRYPT_HASH(op.digestType), nullptr);
        state = util::malloc(hasher->stateSize);
        /* noret */ hasher->initFunc(state);
        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        /* noret */ hasher->appendFunc(state, part.first, part.second);
    }

    /* Finalize */
    {
        unsigned char result[hasher->resultSize];

        /* noret */ hasher->resultFunc(state, result);

        ret = component::Digest(result, hasher->resultSize);
    }

end:

    util::free(state);
    return ret;
}

std::optional<component::MAC> SymCrypt::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;
    uint8_t* state = nullptr;
    uint8_t* expandedKey = nullptr;
    const SYMCRYPT_MAC* mac = nullptr;

    /* Initialize */
    {
        CF_CHECK_NE(mac = SymCrypt_detail::to_SYMCRYPT_MAC(op.digestType), nullptr);

        expandedKey = util::malloc(mac->expandedKeySize);
        CF_CHECK_EQ(mac->expandKeyFunc(
                    expandedKey,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize()), SYMCRYPT_NO_ERROR);

        state = util::malloc(mac->stateSize);
        /* noret */ mac->initFunc(state, expandedKey);

        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        /* noret */ mac->appendFunc(state, part.first, part.second);
    }

    /* Finalize */
    {
        unsigned char result[mac->resultSize];

        /* noret */ mac->resultFunc(state, result);

        ret = component::MAC(result, mac->resultSize);
    }

end:

    util::free(state);
    util::free(expandedKey);
    return ret;
}

std::optional<component::MAC> SymCrypt::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
        case CF_CIPHER("AES_128_CBC_HMAC_SHA1"):
        case CF_CIPHER("AES_128_CBC_HMAC_SHA256"):
        case CF_CIPHER("AES_128_CFB"):
        case CF_CIPHER("AES_128_CFB1"):
        case CF_CIPHER("AES_128_CFB128"):
        case CF_CIPHER("AES_128_CFB8"):
        case CF_CIPHER("AES_128_CTR"):
        case CF_CIPHER("AES_128_ECB"):
        case CF_CIPHER("AES_128_OCB"):
        case CF_CIPHER("AES_128_OFB"):
        case CF_CIPHER("AES_128_WRAP"):
        case CF_CIPHER("AES_128_WRAP_PAD"):
        case CF_CIPHER("AES_128_XTS"):
        case CF_CIPHER("AES_192_CBC"):
        case CF_CIPHER("AES_192_CFB"):
        case CF_CIPHER("AES_192_CFB1"):
        case CF_CIPHER("AES_192_CFB128"):
        case CF_CIPHER("AES_192_CFB8"):
        case CF_CIPHER("AES_192_CTR"):
        case CF_CIPHER("AES_192_ECB"):
        case CF_CIPHER("AES_192_OFB"):
        case CF_CIPHER("AES_192_WRAP"):
        case CF_CIPHER("AES_192_WRAP_PAD"):
        case CF_CIPHER("AES_192_XTS"):
        case CF_CIPHER("AES_256_CBC"):
        case CF_CIPHER("AES_256_CBC_HMAC_SHA1"):
        case CF_CIPHER("AES_256_CFB"):
        case CF_CIPHER("AES_256_CFB1"):
        case CF_CIPHER("AES_256_CFB128"):
        case CF_CIPHER("AES_256_CFB8"):
        case CF_CIPHER("AES_256_CTR"):
        case CF_CIPHER("AES_256_ECB"):
        case CF_CIPHER("AES_256_OCB"):
        case CF_CIPHER("AES_256_OFB"):
        case CF_CIPHER("AES_256_WRAP"):
        case CF_CIPHER("AES_256_WRAP_PAD"):
        case CF_CIPHER("AES_256_XTS"):
        case CF_CIPHER("AES_512_XTS"):
            break;
        default:
            return ret;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;
    SYMCRYPT_AES_CMAC_STATE state;
    SYMCRYPT_AES_CMAC_EXPANDED_KEY expandedKey;

    /* Initialize */
    {
        CF_CHECK_EQ(SymCryptAesCmacExpandKey(
                    &expandedKey,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize()), SYMCRYPT_NO_ERROR);
        /* noret */ SymCryptAesCmacInit(&state, &expandedKey);
        parts = util::ToParts(ds, op.cleartext);
    }

    /* Process */
    for (const auto& part : parts) {
        /* noret */ SymCryptAesCmacAppend(&state, part.first, part.second);
    }

    /* Finalize */
    {
        unsigned char result[SYMCRYPT_AES_CMAC_RESULT_SIZE];

        /* noret */ SymCryptAesCmacResult(&state, result);

        ret = component::MAC(result, SYMCRYPT_AES_CMAC_RESULT_SIZE);
    }

end:

    return ret;
}

namespace SymCrypt_detail {
    std::optional<component::Ciphertext> AES_CCM_Encrypt(operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tagSize == std::nullopt ) {
            return ret;
        }

        SYMCRYPT_AES_EXPANDED_KEY expandedKey;
        SYMCRYPT_CCM_STATE state;
        util::Multipart parts;

        uint8_t* out = util::malloc(op.ciphertextSize);
        uint8_t* tag = util::malloc(*op.tagSize);
        size_t outIdx = 0;

        /* Verify */
        {
            CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
            CF_CHECK_EQ(SymCryptCcmValidateParameters(
                        SymCryptAesBlockCipher,
                        op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        op.cleartext.GetSize(),
                        *op.tagSize), SYMCRYPT_NO_ERROR);
        }

        /* Initialize */
        {

            CF_CHECK_EQ(SymCryptAesExpandKey(
                        &expandedKey,
                        op.cipher.key.GetPtr(),
                        op.cipher.key.GetSize()), SYMCRYPT_NO_ERROR);

            /* noret */ SymCryptCcmInit(
                    &state,
                    SymCryptAesBlockCipher,
                    &expandedKey,
                    op.cipher.iv.GetPtr(),
                    op.cipher.iv.GetSize(),
                    op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                    op.aad != std::nullopt ? op.aad->GetSize() : 0,
                    op.cleartext.GetSize(),
                    *op.tagSize);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            /* noret */ SymCryptCcmEncryptPart(&state, part.first, out + outIdx, part.second);
            outIdx += part.second;
        }

        /* Finalize */
        {
            /* noret */ SymCryptCcmEncryptFinal(&state, tag, *op.tagSize);
            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(tag, *op.tagSize));
        }

end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<component::Ciphertext> AES_GCM_Encrypt(operation::SymmetricEncrypt& op) {
        std::optional<component::Ciphertext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tagSize == std::nullopt ) {
            return ret;
        }

        SYMCRYPT_GCM_EXPANDED_KEY expandedKey;
        SYMCRYPT_GCM_STATE state;
        util::Multipart parts;

        uint8_t* out = util::malloc(op.ciphertextSize);
        uint8_t* tag = util::malloc(*op.tagSize);
        size_t outIdx = 0;

        /* Verify */
        {
            CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
            CF_CHECK_EQ(SymCryptGcmValidateParameters(
                        SymCryptAesBlockCipher,
                        op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        op.cleartext.GetSize(),
                        *op.tagSize), SYMCRYPT_NO_ERROR);
        }

        /* Initialize */
        {

            CF_CHECK_EQ(SymCryptGcmExpandKey(
                        &expandedKey,
                        SymCryptAesBlockCipher,
                        op.cipher.key.GetPtr(),
                        op.cipher.key.GetSize()), SYMCRYPT_NO_ERROR);

            /* noret */ SymCryptGcmInit(
                    &state,
                    &expandedKey,
                    op.cipher.iv.GetPtr(),
                    op.cipher.iv.GetSize());

            if ( op.aad != std::nullopt ) {
                const auto authDataParts = util::ToParts(ds, *op.aad);
                for (const auto& part : authDataParts) {
                    /* noret */ SymCryptGcmAuthPart(&state, part.first, part.second);
                }
            }

            parts = util::ToParts(ds, op.cleartext);
        }


        /* Process */
        for (const auto& part : parts) {
            /* noret */ SymCryptGcmEncryptPart(&state, part.first, out + outIdx, part.second);
            outIdx += part.second;
        }

        /* Finalize */
        {
            /* noret */ SymCryptGcmEncryptFinal(&state, tag, *op.tagSize);
            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(tag, *op.tagSize));
        }

end:
        util::free(out);
        util::free(tag);

        return ret;
    }

    std::optional<component::Cleartext> AES_CCM_Decrypt(operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tag == std::nullopt ) {
            return ret;
        }

        SYMCRYPT_AES_EXPANDED_KEY expandedKey;
        SYMCRYPT_CCM_STATE state;
        util::Multipart parts;

        uint8_t* out = util::malloc(op.cleartextSize);
        size_t outIdx = 0;

        /* Verify */
        {
            CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
            CF_CHECK_EQ(SymCryptCcmValidateParameters(
                        SymCryptAesBlockCipher,
                        op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        op.ciphertext.GetSize(),
                        op.tag->GetSize()), SYMCRYPT_NO_ERROR);
        }

        /* Initialize */
        {

            CF_CHECK_EQ(SymCryptAesExpandKey(
                        &expandedKey,
                        op.cipher.key.GetPtr(),
                        op.cipher.key.GetSize()), SYMCRYPT_NO_ERROR);

            /* noret */ SymCryptCcmInit(
                    &state,
                    SymCryptAesBlockCipher,
                    &expandedKey,
                    op.cipher.iv.GetPtr(),
                    op.cipher.iv.GetSize(),
                    op.aad != std::nullopt ? op.aad->GetPtr() : nullptr,
                    op.aad != std::nullopt ? op.aad->GetSize() : 0,
                    op.ciphertext.GetSize(),
                    op.tag->GetSize());
            parts = util::ToParts(ds, op.ciphertext);
        }

        /* Process */
        for (const auto& part : parts) {
            /* noret */ SymCryptCcmDecryptPart(&state, part.first, out + outIdx, part.second);
            outIdx += part.second;
        }

        /* Finalize */
        {
            CF_CHECK_EQ(SymCryptCcmDecryptFinal(
                    &state,
                    op.tag->GetPtr(),
                    op.tag->GetSize()), SYMCRYPT_NO_ERROR);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
end:
        util::free(out);

        return ret;
    }

    std::optional<component::Cleartext> AES_GCM_Decrypt(operation::SymmetricDecrypt& op) {
        std::optional<component::Cleartext> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.tag == std::nullopt ) {
            return ret;
        }

        SYMCRYPT_GCM_EXPANDED_KEY expandedKey;
        SYMCRYPT_GCM_STATE state;
        util::Multipart parts;

        uint8_t* out = util::malloc(op.cleartextSize);
        size_t outIdx = 0;

        /* Verify */
        {
            CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
            CF_CHECK_EQ(SymCryptGcmValidateParameters(
                        SymCryptAesBlockCipher,
                        op.cipher.iv.GetSize(),
                        op.aad != std::nullopt ? op.aad->GetSize() : 0,
                        op.ciphertext.GetSize(),
                        op.tag->GetSize()), SYMCRYPT_NO_ERROR);
        }

        /* Initialize */
        {

            CF_CHECK_EQ(SymCryptGcmExpandKey(
                        &expandedKey,
                        SymCryptAesBlockCipher,
                        op.cipher.key.GetPtr(),
                        op.cipher.key.GetSize()), SYMCRYPT_NO_ERROR);

            /* noret */ SymCryptGcmInit(
                    &state,
                    &expandedKey,
                    op.cipher.iv.GetPtr(),
                    op.cipher.iv.GetSize());

            if ( op.aad != std::nullopt ) {
                const auto authDataParts = util::ToParts(ds, *op.aad);
                for (const auto& part : authDataParts) {
                    /* noret */ SymCryptGcmAuthPart(&state, part.first, part.second);
                }
            }

            parts = util::ToParts(ds, op.ciphertext);
        }

        /* Process */
        for (const auto& part : parts) {
            /* noret */ SymCryptGcmDecryptPart(&state, part.first, out + outIdx, part.second);
            outIdx += part.second;
        }

        /* Finalize */
        {
            CF_CHECK_EQ(SymCryptGcmDecryptFinal(
                    &state,
                    op.tag->GetPtr(),
                    op.tag->GetSize()), SYMCRYPT_NO_ERROR);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
end:
        util::free(out);

        return ret;
    }

    std::optional<Buffer> ChaCha20(
            const Buffer& in,
            const component::SymmetricKey& key,
            const component::SymmetricIV& iv,
            const Buffer& modifier,
            const size_t maxOutSize)
    {
        std::optional<Buffer> ret = std::nullopt;
        Datasource ds(modifier.GetPtr(), modifier.GetSize());

        SYMCRYPT_CHACHA20_STATE state;
        util::Multipart parts;
        uint8_t* out = nullptr;
        size_t outIdx = 0;

        /* Initialize */
        {
            CF_CHECK_GTE(maxOutSize, in.GetSize());
            out = util::malloc(maxOutSize);
            CF_CHECK_EQ(SymCryptChaCha20Init(
                        &state,
                        key.GetPtr(),
                        key.GetSize(),
                        iv.GetPtr(),
                        iv.GetSize(),
                        0), SYMCRYPT_NO_ERROR);
            parts = util::ToParts(ds, in);
        }

        /* Process */
        for (const auto& part : parts) {
            /* noret */ SymCryptChaCha20Crypt(
                    &state,
                    part.first,
                    out + outIdx,
                    part.second);
            outIdx += part.second;
        }

        /* Finalize */
        ret = Buffer(out, in.GetSize());

end:
        util::free(out);

        return ret;
    }

    std::optional<Buffer> RC4(
            const Buffer& in,
            const component::SymmetricKey& key,
            const size_t maxOutSize)
    {
        std::optional<Buffer> ret = std::nullopt;

        SYMCRYPT_RC4_STATE state;
        uint8_t* out = nullptr;

        /* Initialize */
        {
            CF_CHECK_GTE(maxOutSize, in.GetSize());
            out = util::malloc(maxOutSize);
            CF_CHECK_EQ(SymCryptRc4Init(
                        &state,
                        key.GetPtr(),
                        key.GetSize()), SYMCRYPT_NO_ERROR);
        }

        /* Process */
        /* noret */ SymCryptRc4Crypt(
                &state,
                in.GetPtr(),
                out,
                in.GetSize());

        /* Finalize */
        ret = Buffer(out, in.GetSize());

end:
        util::free(out);

        return ret;
    }

    std::optional<Buffer> AES_XTS(
            const Buffer& in,
            const component::SymmetricKey& key,
            const size_t maxOutSize,
            const bool encrypt)
    {
        std::optional<Buffer> ret = std::nullopt;

        /* XXX workaround for bug */
        if ( in.GetSize() == 0 || in.GetSize() % 16 != 0 ) {
            return ret;
        }

        SYMCRYPT_XTS_AES_EXPANDED_KEY expandedKey;
        uint8_t* out = nullptr;

        /* Initialize */
        {
            CF_CHECK_GTE(maxOutSize, in.GetSize());
            out = util::malloc(maxOutSize);
            CF_CHECK_EQ(SymCryptXtsAesExpandKey(
                        &expandedKey,
                        key.GetPtr(),
                        key.GetSize()), SYMCRYPT_NO_ERROR);
        }

        /* Process */
        if ( encrypt == true ) {
            /* noret */ SymCryptXtsAesEncrypt(
                    &expandedKey,
                    in.GetSize(),
                    0,
                    in.GetPtr(),
                    out,
                    in.GetSize());
        } else {
            /* noret */ SymCryptXtsAesDecrypt(
                    &expandedKey,
                    in.GetSize(),
                    0,
                    in.GetPtr(),
                    out,
                    in.GetSize());
        }

        /* Finalize */
        //ret = Buffer(out, in.GetSize());

end:
        util::free(out);

        return ret;
    }

    std::optional<Buffer> ECB(
            const component::SymmetricCipherType cipherType,
            const Buffer& in,
            const component::SymmetricKey& key,
            const size_t maxOutSize,
            const bool encrypt)
    {
        std::optional<Buffer> ret = std::nullopt;

        const SYMCRYPT_BLOCKCIPHER* cipher = nullptr;
        uint8_t* expandedKey = nullptr;
        uint8_t* out = nullptr;

        /* Initialize */
        {
            CF_CHECK_NE(cipher = SymCrypt_detail::to_SYMCRYPT_BLOCKCIPHER(cipherType), nullptr);
            CF_CHECK_GTE(maxOutSize, in.GetSize());
            expandedKey = util::malloc(cipher->expandedKeySize);
            CF_CHECK_EQ(cipher->expandKeyFunc(
                        expandedKey,
                        key.GetPtr(),
                        key.GetSize()), SYMCRYPT_NO_ERROR);
            CF_CHECK_EQ(in.GetSize() % cipher->blockSize, 0);
            out = util::malloc(maxOutSize);
        }

        /* Process */
        if ( encrypt == true ) {
            /* noret */ SymCryptEcbEncrypt(
                            cipher,
                            expandedKey,
                            in.GetPtr(),
                            out,
                            in.GetSize());
        } else {
            /* noret */ SymCryptEcbDecrypt(
                            cipher,
                            expandedKey,
                            in.GetPtr(),
                            out,
                            in.GetSize());
        }

        /* Finalize */
        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        util::free(expandedKey);

        return ret;
    }

    std::optional<Buffer> CBC(
            const component::SymmetricCipherType cipherType,
            const Buffer& in,
            const component::SymmetricKey& key,
            const component::SymmetricIV& iv,
            const size_t maxOutSize,
            const bool encrypt)
    {
        std::optional<Buffer> ret = std::nullopt;

        const SYMCRYPT_BLOCKCIPHER* cipher = nullptr;
        uint8_t* expandedKey = nullptr;
        uint8_t* out = nullptr;
        uint8_t* chainingValue = nullptr;
        std::vector<uint8_t> inPadded;

        /* Initialize */
        {
            CF_CHECK_NE(cipher = SymCrypt_detail::to_SYMCRYPT_BLOCKCIPHER(cipherType), nullptr);
            if ( encrypt == true ) {
                inPadded = util::Pkcs7Pad(in.Get(), cipher->blockSize);
            } else {
                inPadded = in.Get();
            }
            CF_CHECK_EQ(iv.GetSize(), cipher->blockSize);
            CF_CHECK_GTE(maxOutSize, inPadded.size());
            expandedKey = util::malloc(cipher->expandedKeySize);
            CF_CHECK_EQ(cipher->expandKeyFunc(
                        expandedKey,
                        key.GetPtr(),
                        key.GetSize()), SYMCRYPT_NO_ERROR);
            CF_CHECK_EQ(inPadded.size() % cipher->blockSize, 0);
            out = util::malloc(maxOutSize);
            chainingValue = util::malloc(cipher->blockSize);
            memcpy(chainingValue, iv.GetPtr(), cipher->blockSize);
        }

        /* Process */
        if ( encrypt == true ) {
            /* noret */ SymCryptCbcEncrypt(
                            cipher,
                            expandedKey,
                            chainingValue,
                            inPadded.data(),
                            out,
                            inPadded.size());
            ret = Buffer(out, inPadded.size());
        } else {
            /* noret */ SymCryptCbcDecrypt(
                            cipher,
                            expandedKey,
                            chainingValue,
                            inPadded.data(),
                            out,
                            inPadded.size());
            std::optional<std::vector<uint8_t>> unpadded;
            CF_CHECK_NE(unpadded = util::Pkcs7Unpad(std::vector<uint8_t>(out, out + inPadded.size()), cipher->blockSize), std::nullopt);
            ret = Buffer(out, unpadded->size());
        }

end:
        util::free(out);
        util::free(expandedKey);
        util::free(chainingValue);

        return ret;
    }

    std::optional<Buffer> CFB(
            const component::SymmetricCipherType cipherType,
            const Buffer& in,
            const component::SymmetricKey& key,
            const component::SymmetricIV& iv,
            const size_t maxOutSize,
            const bool encrypt)
    {
        std::optional<Buffer> ret = std::nullopt;

        const SYMCRYPT_BLOCKCIPHER* cipher = nullptr;
        uint8_t* expandedKey = nullptr;
        uint8_t* out = nullptr;
        uint8_t* chainingValue = nullptr;

        /* Initialize */
        {
            CF_CHECK_NE(cipher = SymCrypt_detail::to_SYMCRYPT_BLOCKCIPHER(cipherType), nullptr);
            CF_CHECK_EQ(iv.GetSize(), cipher->blockSize);
            CF_CHECK_GTE(maxOutSize, in.GetSize());
            expandedKey = util::malloc(cipher->expandedKeySize);
            CF_CHECK_EQ(cipher->expandKeyFunc(
                        expandedKey,
                        key.GetPtr(),
                        key.GetSize()), SYMCRYPT_NO_ERROR);
            CF_CHECK_EQ(in.GetSize() % cipher->blockSize, 0);
            out = util::malloc(maxOutSize);
            chainingValue = util::malloc(cipher->blockSize);
            memcpy(chainingValue, iv.GetPtr(), cipher->blockSize);
        }

        /* Process */
        if ( encrypt == true ) {
            /* noret */ SymCryptCfbEncrypt(
                            cipher,
                            cipher->blockSize,
                            expandedKey,
                            chainingValue,
                            in.GetPtr(),
                            out,
                            in.GetSize());
        } else {
            /* noret */ SymCryptCfbDecrypt(
                            cipher,
                            cipher->blockSize,
                            expandedKey,
                            chainingValue,
                            in.GetPtr(),
                            out,
                            in.GetSize());
        }

        /* Finalize */
        ret = Buffer(out, in.GetSize());

end:
        util::free(out);
        util::free(expandedKey);
        util::free(chainingValue);

        return ret;
    }

}

std::optional<component::Ciphertext> SymCrypt::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CCM"):
        case CF_CIPHER("AES_192_CCM"):
        case CF_CIPHER("AES_256_CCM"):
            return SymCrypt_detail::AES_CCM_Encrypt(op);
        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
            return SymCrypt_detail::AES_GCM_Encrypt(op);
            break;
        case CF_CIPHER("CHACHA20"):
            return SymCrypt_detail::ChaCha20(op.cleartext, op.cipher.key, op.cipher.iv, op.modifier, op.ciphertextSize);
        case CF_CIPHER("RC4"):
            return SymCrypt_detail::RC4(op.cleartext, op.cipher.key, op.ciphertextSize);
        case CF_CIPHER("AES_128_XTS"):
        case CF_CIPHER("AES_192_XTS"):
        case CF_CIPHER("AES_256_XTS"):
            return SymCrypt_detail::AES_XTS(op.cleartext, op.cipher.key, op.ciphertextSize, true);
        default:
            if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
                return SymCrypt_detail::ECB(op.cipher.cipherType, op.cleartext, op.cipher.key, op.ciphertextSize, true);
            } else if ( repository::IsCFB(op.cipher.cipherType.Get()) ) {
                return SymCrypt_detail::CFB(op.cipher.cipherType, op.cleartext, op.cipher.key, op.cipher.iv, op.ciphertextSize, true);
            } else if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
                return SymCrypt_detail::CBC(op.cipher.cipherType, op.cleartext, op.cipher.key, op.cipher.iv, op.ciphertextSize, true);
            }
            return ret;
    }

    return ret;
}

std::optional<component::Cleartext> SymCrypt::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;
    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CCM"):
        case CF_CIPHER("AES_192_CCM"):
        case CF_CIPHER("AES_256_CCM"):
            return SymCrypt_detail::AES_CCM_Decrypt(op);
        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
            return SymCrypt_detail::AES_GCM_Decrypt(op);
        case CF_CIPHER("CHACHA20"):
            return SymCrypt_detail::ChaCha20(op.ciphertext, op.cipher.key, op.cipher.iv, op.modifier, op.cleartextSize);
        case CF_CIPHER("RC4"):
            return SymCrypt_detail::RC4(op.ciphertext, op.cipher.key, op.cleartextSize);
        case CF_CIPHER("AES_128_XTS"):
        case CF_CIPHER("AES_192_XTS"):
        case CF_CIPHER("AES_256_XTS"):
            return SymCrypt_detail::AES_XTS(op.ciphertext, op.cipher.key, op.cleartextSize, false);
        default:
            if ( repository::IsECB(op.cipher.cipherType.Get()) ) {
                return SymCrypt_detail::ECB(op.cipher.cipherType, op.ciphertext, op.cipher.key, op.cleartextSize, false);
            } else if ( repository::IsCFB(op.cipher.cipherType.Get()) ) {
                return SymCrypt_detail::CFB(op.cipher.cipherType, op.ciphertext, op.cipher.key, op.cipher.iv, op.cleartextSize, false);
            } else if ( repository::IsCBC(op.cipher.cipherType.Get()) ) {
                return SymCrypt_detail::CBC(op.cipher.cipherType, op.ciphertext, op.cipher.key, op.cipher.iv, op.cleartextSize, false);
            }
            return ret;
    }
    return ret;
}

std::optional<component::Key> SymCrypt::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);
    const SYMCRYPT_MAC* mac = nullptr;

    CF_CHECK_NE(mac = SymCrypt_detail::to_SYMCRYPT_MAC(op.digestType), nullptr);
    CF_CHECK_EQ(SymCryptHkdf(
                mac,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.info.GetPtr(),
                op.info.GetSize(),
                out,
                op.keySize), SYMCRYPT_NO_ERROR);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);
    return ret;
}

std::optional<component::Key> SymCrypt::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);
    const SYMCRYPT_MAC* mac = nullptr;

    CF_CHECK_NE(mac = SymCrypt_detail::to_SYMCRYPT_MAC(op.digestType), nullptr);

    CF_CHECK_EQ(SymCryptPbkdf2(
                mac,
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.iterations,
                out,
                op.keySize), SYMCRYPT_NO_ERROR);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);
    return ret;
}

std::optional<component::Key> SymCrypt::OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("MD5_SHA1"));

    CF_CHECK_EQ(SymCryptTlsPrf1_1(
            op.secret.GetPtr(),
            op.secret.GetSize(),
            nullptr,
            0,
            op.seed.GetPtr(),
            op.seed.GetSize(),
            out,
            op.keySize), SYMCRYPT_NO_ERROR);

    ret = component::Key(out, op.keySize);

end:

    util::free(out);

    return ret;
}

std::optional<component::Key> SymCrypt::OpKDF_SP_800_108(operation::KDF_SP_800_108& op) {
    std::optional<component::Key> ret = std::nullopt;
    uint8_t* out = util::malloc(op.keySize);

    const SYMCRYPT_MAC* mac = nullptr;

    CF_CHECK_EQ(op.mech.mode, true);
    CF_CHECK_EQ(op.mode, 0);
    CF_CHECK_NE(mac = SymCrypt_detail::to_SYMCRYPT_MAC(op.mech.type), nullptr);
    CF_CHECK_EQ(SymCryptSp800_108(
                mac,
                op.secret.GetPtr(),
                op.secret.GetSize(),
                op.label.GetPtr(),
                op.label.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                out,
                op.keySize), SYMCRYPT_NO_ERROR);

    ret = component::Key(out, op.keySize);

end:

    util::free(out);
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
