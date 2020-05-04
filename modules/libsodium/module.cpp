#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <sodium.h>

namespace cryptofuzz {
namespace module {

libsodium::libsodium(void) :
    Module("libsodium") {
    if ( sodium_init() == -1 ) {
        abort();
    }
}

std::optional<component::Digest> libsodium::SHA256(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha256_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        crypto_hash_sha256(out, op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    } else {
        crypto_hash_sha256_state state;

        util::Multipart parts;

        /* Initialize */
        {
            CF_CHECK_EQ(crypto_hash_sha256_init(&state), 0);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(crypto_hash_sha256_update(&state, part.first, part.second), 0);
        }

        /* Finalize */
        {
            CF_CHECK_EQ(crypto_hash_sha256_final(&state, out), 0);
        }

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    }

end:

    return ret;
}

std::optional<component::Digest> libsodium::SHA512(operation::Digest& op) const {
    std::optional<component::Digest> ret = std::nullopt;

    uint8_t out[crypto_hash_sha512_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        crypto_hash_sha512(out, op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha512_BYTES);
    } else {
        crypto_hash_sha512_state state;

        util::Multipart parts;

        /* Initialize */
        {
            CF_CHECK_EQ(crypto_hash_sha512_init(&state), 0);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(crypto_hash_sha512_update(&state, part.first, part.second), 0);
        }

        /* Finalize */
        {
            CF_CHECK_EQ(crypto_hash_sha512_final(&state, out), 0);
        }

        ret = component::Digest(out, crypto_hash_sha512_BYTES);
    }

end:

    return ret;
}

std::optional<component::Digest> libsodium::OpDigest(operation::Digest& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA256"):
            return SHA256(op);
        case CF_DIGEST("SHA512"):
            return SHA512(op);
        default:
            return std::nullopt;
    }
}

std::optional<component::MAC> libsodium::HMAC_SHA256(operation::HMAC& op) const {
    std::optional<component::MAC> ret = std::nullopt;

    uint8_t out[crypto_auth_hmacsha256_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_auth_hmacsha256_KEYBYTES);
        CF_CHECK_EQ(crypto_auth_hmacsha256(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr()), 0);

        ret = component::MAC(out, crypto_auth_hmacsha256_BYTES);
    } else {
        crypto_auth_hmacsha256_state state;

        util::Multipart parts;

        /* Initialize */
        {
            CF_CHECK_EQ(crypto_auth_hmacsha256_init(&state, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(crypto_auth_hmacsha256_update(&state, part.first, part.second), 0);
        }

        /* Finalize */
        {
            CF_CHECK_EQ(crypto_auth_hmacsha256_final(&state, out), 0);
        }

        ret = component::MAC(out, crypto_auth_hmacsha256_BYTES);
    }

end:

    return ret;
}

std::optional<component::MAC> libsodium::HMAC_SHA512(operation::HMAC& op) const {
    std::optional<component::MAC> ret = std::nullopt;

    uint8_t out[crypto_auth_hmacsha512_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_auth_hmacsha512_KEYBYTES);
        CF_CHECK_EQ(crypto_auth_hmacsha512(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr()), 0);

        ret = component::MAC(out, crypto_auth_hmacsha512_BYTES);
    } else {
        crypto_auth_hmacsha512_state state;

        util::Multipart parts;

        /* Initialize */
        {
            CF_CHECK_EQ(crypto_auth_hmacsha512_init(&state, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(crypto_auth_hmacsha512_update(&state, part.first, part.second), 0);
        }

        /* Finalize */
        {
            CF_CHECK_EQ(crypto_auth_hmacsha512_final(&state, out), 0);
        }

        ret = component::MAC(out, crypto_auth_hmacsha512_BYTES);
    }

end:

    return ret;
}

std::optional<component::MAC> libsodium::HMAC_SHA512256(operation::HMAC& op) const {
    std::optional<component::MAC> ret = std::nullopt;

    uint8_t out[crypto_auth_hmacsha512256_BYTES];

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool doMulti = false;
    try {
        doMulti = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( doMulti == false ) {
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_auth_hmacsha512256_KEYBYTES);
        CF_CHECK_EQ(crypto_auth_hmacsha512256(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr()), 0);

        //ret = component::MAC(out, crypto_auth_hmacsha512256_BYTES);
    } else {
        crypto_auth_hmacsha512256_state state;

        util::Multipart parts;

        /* Initialize */
        {
            CF_CHECK_EQ(crypto_auth_hmacsha512256_init(&state, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
            parts = util::ToParts(ds, op.cleartext);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(crypto_auth_hmacsha512256_update(&state, part.first, part.second), 0);
        }

        /* Finalize */
        {
            CF_CHECK_EQ(crypto_auth_hmacsha512256_final(&state, out), 0);
        }

        //ret = component::MAC(out, crypto_auth_hmacsha512256_BYTES);
    }

end:

    return ret;
}

std::optional<component::MAC> libsodium::SIPHASH64(operation::HMAC& op) const {
    std::optional<component::MAC> ret = std::nullopt;
    uint8_t out[crypto_shorthash_BYTES];

    /* Initialize */
    {
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_shorthash_KEYBYTES);
    }

    /* Process */
    {
        CF_CHECK_EQ(crypto_shorthash(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr()), 0);
    }

    /* Finalize */
    {
        ret = component::MAC(out, crypto_shorthash_BYTES);
    }

end:

    return ret;
}

std::optional<component::MAC> libsodium::SIPHASH128(operation::HMAC& op) const {
    std::optional<component::MAC> ret = std::nullopt;
    uint8_t out[crypto_shorthash_siphashx24_BYTES];

    /* Initialize */
    {
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_shorthash_siphashx24_KEYBYTES);
    }

    /* Process */
    {
        CF_CHECK_EQ(crypto_shorthash_siphashx24(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr()), 0);
    }

    /* Finalize */
    {
        ret = component::MAC(out, crypto_shorthash_siphashx24_BYTES);
    }

end:

    return ret;
}



std::optional<component::MAC> libsodium::OpHMAC(operation::HMAC& op) {
    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA256"):
            return HMAC_SHA256(op);
        case CF_DIGEST("SHA512"):
            return HMAC_SHA512(op);
        case CF_DIGEST("SHA512-256"):
            return HMAC_SHA512256(op);
        case CF_DIGEST("SIPHASH64"):
            return SIPHASH64(op);
        case CF_DIGEST("SIPHASH128"):
            return SIPHASH128(op);
        default:
            return std::nullopt;
    }
}

namespace libsodium_detail {

template <size_t TAGLEN, size_t IVLEN, size_t KEYLEN>
class AEAD {
    private:
        virtual int encrypt(unsigned char *c,
                unsigned long long *clen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *nsec,
                const unsigned char *npub,
                const unsigned char *k) const = 0;
        virtual int decrypt(unsigned char *m,
                unsigned long long *mlen,
                unsigned char *nsec,
                const unsigned char *c,
                unsigned long long clen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *npub,
                const unsigned char *k) const = 0;
    public:
        std::optional<component::Ciphertext> Encrypt(const operation::SymmetricEncrypt& op) const {
            std::optional<component::Ciphertext> ret = std::nullopt;

            uint8_t* out = util::malloc(op.ciphertextSize);

            /* Operation must support tag output */
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_GTE(op.tagSize, TAGLEN);

            /* Output must be able to hold message + tag */
            CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize() + TAGLEN);

            CF_CHECK_EQ(op.cipher.iv.GetSize(), IVLEN);
            CF_CHECK_EQ(op.cipher.key.GetSize(), KEYLEN);

            unsigned long long ciphertext_len;

            CF_CHECK_EQ(encrypt(
                        out,
                        &ciphertext_len,
                        op.cleartext.GetPtr(),
                        op.cleartext.GetSize(),
                        op.aad == std::nullopt ? (const uint8_t*)0x12 : op.aad->GetPtr(),
                        op.aad == std::nullopt ? 0: op.aad->GetSize(),
                        nullptr,
                        op.cipher.iv.GetPtr(),
                        op.cipher.key.GetPtr()), 0);

            if ( ciphertext_len > op.cleartext.GetSize() + TAGLEN ) {
                abort();
            }
            if ( ciphertext_len < TAGLEN ) {
                abort();
            }

            ret = component::Ciphertext(
                    Buffer(out, ciphertext_len - TAGLEN),
                    Buffer(out + ciphertext_len - TAGLEN, TAGLEN));
end:
            util::free(out);
            return ret;
        }

        std::optional<component::Cleartext> Decrypt(const operation::SymmetricDecrypt& op) const {
            std::optional<component::Cleartext> ret = std::nullopt;

            size_t ciphertextAndTagSize;
            uint8_t* ciphertextAndTag = nullptr;
            uint8_t* out = nullptr;

            CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());

            CF_CHECK_NE(op.tag, std::nullopt);

            /* Concatenate ciphertext + tag */
            {
                ciphertextAndTagSize = op.ciphertext.GetSize() + op.tag->GetSize();
                ciphertextAndTag = util::malloc(ciphertextAndTagSize);

                if ( op.ciphertext.GetSize() ) {
                    memcpy(ciphertextAndTag, op.ciphertext.GetPtr(), op.ciphertext.GetSize());
                }
                if ( op.tag->GetSize() ) {
                    memcpy(ciphertextAndTag + op.ciphertext.GetSize(), op.tag->GetPtr(), op.tag->GetSize());
                }
            }

            CF_CHECK_EQ(op.tag->GetSize(), TAGLEN);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), IVLEN);
            CF_CHECK_EQ(op.cipher.key.GetSize(), KEYLEN);

            out = util::malloc(op.cleartextSize);

            unsigned long long cleartext_len;

            CF_CHECK_EQ(decrypt(
                        out,
                        &cleartext_len,
                        nullptr,
                        ciphertextAndTag,
                        ciphertextAndTagSize,
                        op.aad == std::nullopt ? (const uint8_t*)0x12 : op.aad->GetPtr(),
                        op.aad == std::nullopt ? 0: op.aad->GetSize(),
                        op.cipher.iv.GetPtr(),
                        op.cipher.key.GetPtr()), 0);

            ret = component::Cleartext(out, cleartext_len);

end:
            util::free(ciphertextAndTag);
            util::free(out);

            return ret;
        }
};

static class : public AEAD<
                                crypto_aead_aes256gcm_ABYTES,
                                crypto_aead_aes256gcm_NPUBBYTES,
                                crypto_aead_aes256gcm_KEYBYTES> {
    private:
        int encrypt(unsigned char *c,
                unsigned long long *clen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *nsec,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_aes256gcm_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
        }

        int decrypt(unsigned char *m,
                unsigned long long *mlen,
                unsigned char *nsec,
                const unsigned char *c,
                unsigned long long clen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_aes256gcm_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
        }
} aes_256_gcm;

static class : public AEAD<
                                crypto_aead_aes256gcm_ABYTES,
                                crypto_aead_aes256gcm_NPUBBYTES,
                                crypto_aead_aes256gcm_KEYBYTES> {
    private:
        int encrypt(unsigned char *c,
                unsigned long long *clen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *nsec,
                const unsigned char *npub,
                const unsigned char *k) const override {
            int ret = -1;

            crypto_aead_aes256gcm_state ctx;
            CF_CHECK_EQ(crypto_aead_aes256gcm_beforenm(&ctx, k), 0);

            CF_CHECK_EQ(crypto_aead_aes256gcm_encrypt_afternm(c, clen, m, mlen, ad, adlen, nsec, npub, &ctx), 0);

            ret = 0;

end:
            return ret;
        }

        int decrypt(unsigned char *m,
                unsigned long long *mlen,
                unsigned char *nsec,
                const unsigned char *c,
                unsigned long long clen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *npub,
                const unsigned char *k) const override {
            int ret = -1;
            crypto_aead_aes256gcm_state ctx;
            CF_CHECK_EQ(crypto_aead_aes256gcm_beforenm(&ctx, k), 0);

            CF_CHECK_EQ(crypto_aead_aes256gcm_decrypt_afternm(m, mlen, nsec, c, clen, ad, adlen, npub, &ctx), 0);

            ret = 0;
end:
            return ret;
        }
} aes_256_gcm_precompute;

static class : public AEAD<
                                crypto_aead_chacha20poly1305_ABYTES,
                                crypto_aead_chacha20poly1305_NPUBBYTES,
                                crypto_aead_chacha20poly1305_KEYBYTES> {
    private:
        int encrypt(unsigned char *c,
                unsigned long long *clen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *nsec,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_chacha20poly1305_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
        }

        int decrypt(unsigned char *m,
                unsigned long long *mlen,
                unsigned char *nsec,
                const unsigned char *c,
                unsigned long long clen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_chacha20poly1305_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
        }
} chacha20_poly1305_libsodium;

static class : public AEAD<
                                crypto_aead_chacha20poly1305_IETF_ABYTES,
                                crypto_aead_chacha20poly1305_IETF_NPUBBYTES,
                                crypto_aead_chacha20poly1305_IETF_KEYBYTES> {
    private:
        int encrypt(unsigned char *c,
                unsigned long long *clen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *nsec,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_chacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
        }

        int decrypt(unsigned char *m,
                unsigned long long *mlen,
                unsigned char *nsec,
                const unsigned char *c,
                unsigned long long clen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_chacha20poly1305_ietf_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
        }
} chacha20_poly1305;

static class : public AEAD<
                                crypto_aead_xchacha20poly1305_IETF_ABYTES,
                                crypto_aead_xchacha20poly1305_IETF_NPUBBYTES,
                                crypto_aead_xchacha20poly1305_IETF_KEYBYTES> {
    private:
        int encrypt(unsigned char *c,
                unsigned long long *clen,
                const unsigned char *m,
                unsigned long long mlen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *nsec,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_xchacha20poly1305_ietf_encrypt(c, clen, m, mlen, ad, adlen, nsec, npub, k);
        }

        int decrypt(unsigned char *m,
                unsigned long long *mlen,
                unsigned char *nsec,
                const unsigned char *c,
                unsigned long long clen,
                const unsigned char *ad,
                unsigned long long adlen,
                const unsigned char *npub,
                const unsigned char *k) const override {
            return crypto_aead_xchacha20poly1305_ietf_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
        }
} xchacha20_poly1305;

} /* namespace libsodium_detail */

std::optional<component::Ciphertext> libsodium::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    uint8_t* out = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("AES_256_GCM"):
            {
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                bool usePrecomputation = false;
                try {
                    usePrecomputation = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) {
                }

                if ( usePrecomputation == false ) {
                    return libsodium_detail::aes_256_gcm.Encrypt(op);
                } else {
                    return libsodium_detail::aes_256_gcm_precompute.Encrypt(op);
                }
            }
            break;
        case    CF_CIPHER("CHACHA20_POLY1305_LIBSODIUM"):
            {
                return libsodium_detail::chacha20_poly1305_libsodium.Encrypt(op);
            }
            break;
        case    CF_CIPHER("CHACHA20_POLY1305"):
            {
                return libsodium_detail::chacha20_poly1305.Encrypt(op);
            }
            break;
        case    CF_CIPHER("XCHACHA20_POLY1305"):
            {
                return libsodium_detail::xchacha20_poly1305.Encrypt(op);
            }
            break;
        case    CF_CIPHER("CHACHA20"):
            {
                CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());
                CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_stream_chacha20_ietf_KEYBYTES);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_stream_chacha20_ietf_NONCEBYTES);
                out = util::malloc(op.ciphertextSize);
                CF_CHECK_EQ(crypto_stream_chacha20_ietf_xor_ic(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.iv.GetPtr(), 0, op.cipher.key.GetPtr()), 0);
                auto ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
                util::free(out);
                return ret;
            }
            break;
        default:
            return std::nullopt;
    }

end:
    util::free(out);
    return std::nullopt;
}

std::optional<component::Cleartext> libsodium::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    uint8_t* out = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("AES_256_GCM"):
            {
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
                bool usePrecomputation = false;
                try {
                    usePrecomputation = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) {
                }

                if ( usePrecomputation == false ) {
                    return libsodium_detail::aes_256_gcm.Decrypt(op);
                } else {
                    return libsodium_detail::aes_256_gcm_precompute.Decrypt(op);
                }
            }
            break;
        case    CF_CIPHER("CHACHA20_POLY1305_LIBSODIUM"):
            {
                return libsodium_detail::chacha20_poly1305_libsodium.Decrypt(op);
            }
            break;
        case    CF_CIPHER("CHACHA20_POLY1305"):
            {
                return libsodium_detail::chacha20_poly1305.Decrypt(op);
            }
            break;
        case    CF_CIPHER("XCHACHA20_POLY1305"):
            {
                return libsodium_detail::xchacha20_poly1305.Decrypt(op);
            }
            break;
        case    CF_CIPHER("CHACHA20"):
            {
                CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
                CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_stream_chacha20_ietf_KEYBYTES);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_stream_chacha20_ietf_NONCEBYTES);
                out = util::malloc(op.cleartextSize);
                CF_CHECK_EQ(crypto_stream_chacha20_ietf_xor_ic(out, op.ciphertext.GetPtr(), op.ciphertext.GetSize(), op.cipher.iv.GetPtr(), 0, op.cipher.key.GetPtr()), 0);
                auto ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
                util::free(out);
                return ret;
            }
            break;
        default:
            return std::nullopt;
    }

end:
    util::free(out);
    return std::nullopt;
}

std::optional<component::Key> libsodium::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(op.salt.GetSize(), crypto_pwhash_SALTBYTES);
    CF_CHECK_EQ(op.threads, 1);
    CF_CHECK_GTE(op.keySize, crypto_pwhash_BYTES_MIN);
    CF_CHECK_GTE(op.password.GetSize(), crypto_pwhash_PASSWD_MIN);
    CF_CHECK_LTE(op.password.GetSize(), crypto_pwhash_PASSWD_MAX);
    CF_CHECK_GTE(op.iterations, crypto_pwhash_OPSLIMIT_MIN);
    CF_CHECK_LTE(op.iterations, crypto_pwhash_OPSLIMIT_MAX);
    CF_CHECK_GTE(op.memory * 1024, crypto_pwhash_MEMLIMIT_MIN);
    //CF_CHECK_LTE(op.memory, crypto_pwhash_MEMLIMIT_MAX);

    CF_CHECK_EQ(op.type == 1 || op.type == 2, true);
    CF_CHECK_EQ(crypto_pwhash(
                out,
                op.keySize,
                (const char*)op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.iterations,
                op.memory * 1024,
                op.type == 1 ? crypto_pwhash_ALG_ARGON2I13 : crypto_pwhash_ALG_ARGON2ID13
            ), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> libsodium::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;

    const size_t outSize = op.keySize;
    uint8_t* out = util::malloc(outSize);

    CF_CHECK_EQ(crypto_pwhash_scryptsalsa208sha256_ll(
        op.password.GetPtr(),
        op.password.GetSize(),
        op.salt.GetPtr(),
        op.salt.GetSize(),
        op.N,
        op.r,
        op.p,
        out,
        outSize), 0);

    ret = component::Key(out, outSize);

end:
    util::free(out);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
