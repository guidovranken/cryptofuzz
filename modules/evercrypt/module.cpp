#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>

#define crypto_hash_md5_BYTES    EverCrypt_Hash_tagLen(Spec_Hash_Definitions_MD5)
#define crypto_hash_sha1_BYTES   EverCrypt_Hash_tagLen(Spec_Hash_Definitions_SHA1)
#define crypto_hash_sha224_BYTES EverCrypt_Hash_tagLen(Spec_Hash_Definitions_SHA2_224)
#define crypto_hash_sha256_BYTES EverCrypt_Hash_tagLen(Spec_Hash_Definitions_SHA2_256)
#define crypto_hash_sha384_BYTES EverCrypt_Hash_tagLen(Spec_Hash_Definitions_SHA2_384)
#define crypto_hash_sha512_BYTES EverCrypt_Hash_tagLen(Spec_Hash_Definitions_SHA2_512)

#define crypto_auth_hmacsha1_BYTES   crypto_hash_sha1_BYTES
#define crypto_auth_hmacsha256_BYTES crypto_hash_sha256_BYTES
#define crypto_auth_hmacsha384_BYTES crypto_hash_sha384_BYTES
#define crypto_auth_hmacsha512_BYTES crypto_hash_sha512_BYTES

namespace cryptofuzz {
namespace module {

EverCrypt::EverCrypt(void) :
    Module("EverCrypt") {
  EverCrypt_AutoConfig2_init();
}

std::optional<component::Digest> EverCrypt::MD5(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_md5_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_MD5, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_md5_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

        /* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_MD5);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_MD5, st, (uint8_t*)part.first, part.second);
        }

        /* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_MD5, st, out);
            EverCrypt_Hash_free(st.hash_state);
            free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_md5_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA1(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha1_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA1, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha1_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

        /* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA1);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA1, st, (uint8_t*)part.first, part.second);
        }

        /* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA1, st, out);
            EverCrypt_Hash_free(st.hash_state);
            free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha1_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA224(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha224_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_224, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha224_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

        /* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_224);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_224, st, (uint8_t*)part.first, part.second);
        }

        /* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_224, st, out);
            EverCrypt_Hash_free(st.hash_state);
            free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha224_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA256(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha256_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_256, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

        /* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_256);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_256, st, (uint8_t*)part.first, part.second);
        }

        /* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_256, st, out);
            EverCrypt_Hash_free(st.hash_state);
            free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA384(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha384_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_384, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha384_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

        /* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_384);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_384, st, (uint8_t*)part.first, part.second);
        }

        /* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_384, st, out);
            EverCrypt_Hash_free(st.hash_state);
            free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha384_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::SHA512(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha512_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        EverCrypt_Hash_hash(Spec_Hash_Definitions_SHA2_512, out, (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha512_BYTES);
    } else {
        EverCrypt_Hash_Incremental_state st;

        util::Multipart parts;

        /* Initialize */
        {
            st = EverCrypt_Hash_Incremental_create_in(Spec_Hash_Definitions_SHA2_512);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            st = EverCrypt_Hash_Incremental_update(Spec_Hash_Definitions_SHA2_512, st, (uint8_t*)part.first, part.second);
        }

        /* Finalize */
        {
            EverCrypt_Hash_Incremental_finish(Spec_Hash_Definitions_SHA2_512, st, out);
            EverCrypt_Hash_free(st.hash_state);
            free(st.buf);
        }

        ret = component::Digest(out, crypto_hash_sha512_BYTES);
    }

    return ret;
}

std::optional<component::Digest> EverCrypt::OpDigest(operation::Digest& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("MD5"):
            return MD5(op);
        case CF_DIGEST("SHA1"):
            return SHA1(op);
        case CF_DIGEST("SHA224"):
            return SHA224(op);
        case CF_DIGEST("SHA256"):
            return SHA256(op);
        case CF_DIGEST("SHA384"):
            return SHA384(op);
        case CF_DIGEST("SHA512"):
            return SHA512(op);
        default:
            return std::nullopt;
    }
}

std::optional<component::MAC> EverCrypt::HMAC(Spec_Hash_Definitions_hash_alg alg, uint32_t mac_len, operation::HMAC& op) const {
    std::optional<component::MAC> ret = std::nullopt;

    uint8_t out[mac_len];

    EverCrypt_HMAC_compute(alg, out, (uint8_t*)op.cipher.key.GetPtr(), op.cipher.key.GetSize(), (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize());

    ret = component::MAC(out, mac_len);

    return ret;
}

std::optional<component::MAC> EverCrypt::OpHMAC(operation::HMAC& op) {
   switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            return HMAC(Spec_Hash_Definitions_SHA1, crypto_auth_hmacsha1_BYTES, op);
        case CF_DIGEST("SHA256"):
            return HMAC(Spec_Hash_Definitions_SHA2_256, crypto_auth_hmacsha256_BYTES, op);
        case CF_DIGEST("SHA384"):
            return HMAC(Spec_Hash_Definitions_SHA2_384, crypto_auth_hmacsha384_BYTES, op);
        case CF_DIGEST("SHA512"):
            return HMAC(Spec_Hash_Definitions_SHA2_512, crypto_auth_hmacsha512_BYTES, op);
        default:
            return std::nullopt;
    }
}

std::optional<component::Key> EverCrypt::HKDF(Spec_Hash_Definitions_hash_alg alg, uint32_t hash_len, operation::KDF_HKDF& op) const {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t prk[hash_len];
    uint8_t* okm = nullptr;

    size_t okm_size = op.keySize;

    CF_CHECK_LTE(okm_size, 255*hash_len);

    okm = util::malloc(okm_size);

    /* Extract */
    {
      EverCrypt_HKDF_hkdf_extract(alg, prk, (uint8_t*)op.salt.GetPtr(), op.salt.GetSize(), (uint8_t*)op.password.GetPtr(), op.password.GetSize());
    }

    /* Expand */
    {
        EverCrypt_HKDF_hkdf_expand(alg, okm, prk, hash_len, (uint8_t*)op.info.GetPtr(), op.info.GetSize(), okm_size);
        ret = component::Key(okm, okm_size);
    }

    util::free(okm);

end:
    return ret;
}

std::optional<component::Key> EverCrypt::OpKDF_HKDF(operation::KDF_HKDF& op) {
   switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            return HKDF(Spec_Hash_Definitions_SHA1, crypto_hash_sha1_BYTES, op);
        case CF_DIGEST("SHA256"):
            return HKDF(Spec_Hash_Definitions_SHA2_256, crypto_hash_sha256_BYTES, op);
        case CF_DIGEST("SHA384"):
            return HKDF(Spec_Hash_Definitions_SHA2_384, crypto_hash_sha384_BYTES, op);
        case CF_DIGEST("SHA512"):
            return HKDF(Spec_Hash_Definitions_SHA2_512, crypto_hash_sha512_BYTES, op);
        default:
            return std::nullopt;
    }
}

namespace evercrypt_aead {

template <uint8_t ALG, size_t TAGLEN, size_t IVLEN, size_t KEYLEN>
class AEAD {
    public:
        std::optional<component::Ciphertext> Encrypt(operation::SymmetricEncrypt& op) const {
            std::optional<component::Ciphertext> ret = std::nullopt;

            uint8_t* out = util::malloc(op.ciphertextSize);

            uint8_t* ek = nullptr;
            unsigned long long ciphertext_len = op.cleartext.GetSize() + TAGLEN;

            /* Operation must support tag output */
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_GTE(op.tagSize, TAGLEN);

            /* Output must be able to hold message + tag */
            CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize() + TAGLEN);

            CF_CHECK_EQ(op.cipher.iv.GetSize(), IVLEN);
            CF_CHECK_EQ(op.cipher.key.GetSize(), KEYLEN);

            ek = EverCrypt_AEAD_expand_in(ALG, (uint8_t*)op.cipher.key.GetPtr());

            CF_CHECK_EQ(EverCrypt_AEAD_encrypt(ALG,
                                               ek,
                                               (uint8_t*)op.cipher.iv.GetPtr(),
                                               (uint8_t*)(op.aad == std::nullopt ? (const uint8_t*)0x12 : op.aad->GetPtr()),
                                               op.aad == std::nullopt ? 0: op.aad->GetSize(),
                                               (uint8_t*)op.cleartext.GetPtr(),
                                               op.cleartext.GetSize(),
                                               out,
                                               out + ciphertext_len - TAGLEN), EverCrypt_AEAD_Success)


            ret = component::Ciphertext(
                            Buffer(out, ciphertext_len - TAGLEN),
                            Buffer(out + ciphertext_len - TAGLEN, TAGLEN));

end:
            util::free(out);
            util::free(ek);

            return ret;
        }

        std::optional<component::Cleartext> Decrypt(operation::SymmetricDecrypt& op) const {
            std::optional<component::Cleartext> ret = std::nullopt;

            uint8_t* out = util::malloc(op.ciphertext.GetSize());
            uint8_t* ek = nullptr;

            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_GTE(op.tag->GetSize(), TAGLEN);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), IVLEN);
            CF_CHECK_EQ(op.cipher.key.GetSize(), KEYLEN);

            ek = EverCrypt_AEAD_expand_in(ALG, (uint8_t*)op.cipher.key.GetPtr());

            CF_CHECK_EQ(EverCrypt_AEAD_decrypt(ALG,
                                               ek,
                                               (uint8_t*)op.cipher.iv.GetPtr(),
                                               (uint8_t*)(op.aad == std::nullopt ? (const uint8_t*)0x12 : op.aad->GetPtr()),
                                               op.aad == std::nullopt ? 0: op.aad->GetSize(),
                                               (uint8_t*)op.ciphertext.GetPtr(),
                                               op.ciphertext.GetSize(),
                                               (uint8_t*)op.tag->GetPtr(),
                                               out), EverCrypt_AEAD_Success)


            ret = component::Cleartext(out, op.ciphertext.GetSize());

end:
            util::free(out);
            util::free(ek);

            return ret;
        }

};

static class : public AEAD<Spec_AEAD_AES128_GCM, 16, 12, 16> { } aes_128_gcm;

static class : public AEAD<Spec_AEAD_AES256_GCM, 16, 12, 32> { } aes_256_gcm;

static class : public AEAD<Spec_AEAD_CHACHA20_POLY1305, 16, 12, 32> { } chacha20_poly1305;

} /* namespace evercrypt_aead */


std::optional<component::Ciphertext> EverCrypt::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    switch ( op.cipher.cipherType.Get() ) {
    case CF_CIPHER("AES_128_GCM"):
        return evercrypt_aead::aes_128_gcm.Encrypt(op);
    case CF_CIPHER("AES_256_GCM"):
        return evercrypt_aead::aes_256_gcm.Encrypt(op);
    case CF_CIPHER("CHACHA20_POLY1305"):
        return evercrypt_aead::chacha20_poly1305.Encrypt(op);
    default:
        return std::nullopt;
    }
}

std::optional<component::Cleartext> EverCrypt::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    switch ( op.cipher.cipherType.Get() ) {
    case CF_CIPHER("AES_128_GCM"):
        return evercrypt_aead::aes_128_gcm.Decrypt(op);
    case CF_CIPHER("AES_256_GCM"):
        return evercrypt_aead::aes_256_gcm.Decrypt(op);
    case CF_CIPHER("CHACHA20_POLY1305"):
        return evercrypt_aead::chacha20_poly1305.Decrypt(op);
    default:
        return std::nullopt;
    }
}


} /* namespace module */
} /* namespace cryptofuzz */
