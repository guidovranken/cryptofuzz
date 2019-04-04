#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
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
    using fuzzing::datasource::ID;

    std::optional<component::Digest> ret = std::nullopt;

    if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA256") ) {
        ret = SHA256(op);
    } else if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA512") ) {
        ret = SHA512(op);
    }

    return ret;
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

        ret = component::MAC(out, crypto_auth_hmacsha512256_BYTES);
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

        ret = component::MAC(out, crypto_auth_hmacsha512256_BYTES);
    }

end:

    return ret;
}

std::optional<component::MAC> libsodium::OpHMAC(operation::HMAC& op) {
    using fuzzing::datasource::ID;

    std::optional<component::MAC> ret = std::nullopt;

    if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA256") ) {
        ret = HMAC_SHA256(op);
    } else if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA512") ) {
        ret = HMAC_SHA512(op);
    } else if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA512-256") ) {
        ret = HMAC_SHA512256(op);
    }

    return ret;
}

std::optional<component::Ciphertext> libsodium::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Ciphertext> ret = std::nullopt;

    uint8_t* out = util::malloc(op.ciphertextSize);

    if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/AES_256_CBC") ) {
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize() + crypto_aead_aes256gcm_ABYTES);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_aes256gcm_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_aes256gcm_KEYBYTES);

        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        bool usePrecomputation = false;
        try {
            usePrecomputation = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        if ( usePrecomputation == false ) {
            unsigned long long ciphertext_len;

            CF_CHECK_EQ(crypto_aead_aes256gcm_encrypt(
                        out,
                        &ciphertext_len,
                        op.cleartext.GetPtr(),
                        op.cleartext.GetSize(),
                        (unsigned char*)0x12,
                        0,
                        NULL,
                        op.cipher.iv.GetPtr(),
                        op.cipher.key.GetPtr()), 0);

            ret = component::Ciphertext(out, ciphertext_len);
        } else {
            unsigned long long ciphertext_len;

            crypto_aead_aes256gcm_state ctx;
            CF_CHECK_EQ(crypto_aead_aes256gcm_beforenm(&ctx, op.cipher.key.GetPtr()), 0);

            CF_CHECK_EQ(crypto_aead_aes256gcm_encrypt_afternm(
                        out,
                        &ciphertext_len,
                        op.cleartext.GetPtr(),
                        op.cleartext.GetSize(),
                        (unsigned char*)0x12,
                        0,
                        NULL,
                        op.cipher.iv.GetPtr(),
                        &ctx), 0);

            ret = component::Ciphertext(out, ciphertext_len);
        }
    } else if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/CHACHA20_POLY1305_LIBSODIUM") ) {
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize() + crypto_aead_chacha20poly1305_ABYTES);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_chacha20poly1305_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_chacha20poly1305_KEYBYTES);

        unsigned long long ciphertext_len;

        CF_CHECK_EQ(crypto_aead_chacha20poly1305_encrypt(
                out,
                &ciphertext_len,
                op.cleartext.GetPtr(),
                op.cleartext.GetSize(),
                (unsigned char*)0x12,
                0,
                NULL,
                op.cipher.iv.GetPtr(),
                op.cipher.key.GetPtr()), 0);

        ret = component::Ciphertext(out, ciphertext_len);
    } else if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/CHACHA20_POLY1305") ) {
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize() + crypto_aead_chacha20poly1305_IETF_ABYTES);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_chacha20poly1305_IETF_KEYBYTES);

        unsigned long long ciphertext_len;

        CF_CHECK_EQ(crypto_aead_chacha20poly1305_ietf_encrypt(
                out,
                &ciphertext_len,
                op.cleartext.GetPtr(),
                op.cleartext.GetSize(),
                (unsigned char*)0x12,
                0,
                NULL,
                op.cipher.iv.GetPtr(),
                op.cipher.key.GetPtr()), 0);

        ret = component::Ciphertext(out, ciphertext_len);
    } else if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/XCHACHA20_POLY1305") ) {
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize() + crypto_aead_xchacha20poly1305_IETF_ABYTES);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_xchacha20poly1305_IETF_KEYBYTES);

        unsigned long long ciphertext_len;

        CF_CHECK_EQ(crypto_aead_xchacha20poly1305_ietf_encrypt(
                out,
                &ciphertext_len,
                op.cleartext.GetPtr(),
                op.cleartext.GetSize(),
                (unsigned char*)0x12,
                0,
                NULL,
                op.cipher.iv.GetPtr(),
                op.cipher.key.GetPtr()), 0);

        ret = component::Ciphertext(out, ciphertext_len);
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::Cleartext> libsodium::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Cleartext> ret = std::nullopt;

    uint8_t* out = nullptr;

    if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/AES_256_CBC") ) {
        CF_CHECK_GTE(op.ciphertext.GetSize(), crypto_aead_aes256gcm_ABYTES);

        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_aes256gcm_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_aes256gcm_KEYBYTES);

        out = util::malloc(op.cleartextSize);

        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        bool usePrecomputation = false;
        try {
            usePrecomputation = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) {
        }

        if ( usePrecomputation == false ) {
            unsigned long long cleartext_len;

            CF_CHECK_EQ(crypto_aead_aes256gcm_decrypt(
                        out,
                        &cleartext_len,
                        NULL,
                        op.ciphertext.GetPtr(),
                        op.ciphertext.GetSize(),
                        (unsigned char*)0x12,
                        0,
                        op.cipher.iv.GetPtr(),
                        op.cipher.key.GetPtr()), 0);

            ret = component::Cleartext(out, cleartext_len);
        } else {
            unsigned long long cleartext_len;

            crypto_aead_aes256gcm_state ctx;
            CF_CHECK_EQ(crypto_aead_aes256gcm_beforenm(&ctx, op.cipher.key.GetPtr()), 0);

            CF_CHECK_EQ(crypto_aead_aes256gcm_decrypt_afternm(
                        out,
                        &cleartext_len,
                        NULL,
                        op.ciphertext.GetPtr(),
                        op.ciphertext.GetSize(),
                        (unsigned char*)0x12,
                        0,
                        op.cipher.iv.GetPtr(),
                        &ctx), 0);

            ret = component::Ciphertext(out, cleartext_len);
        }
    } else if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/CHACHA20_POLY1305_LIBSODIUM") ) {
        CF_CHECK_GTE(op.ciphertext.GetSize(), crypto_aead_chacha20poly1305_ABYTES);

        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_chacha20poly1305_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_chacha20poly1305_KEYBYTES);

        out = util::malloc(op.cleartextSize);

        unsigned long long cleartext_len;

        CF_CHECK_EQ(crypto_aead_chacha20poly1305_decrypt(
                out,
                &cleartext_len,
                NULL,
                op.ciphertext.GetPtr(),
                op.ciphertext.GetSize(),
                (unsigned char*)0x12,
                0,
                op.cipher.iv.GetPtr(),
                op.cipher.key.GetPtr()), 0);

        ret = component::Cleartext(out, cleartext_len);
    } else if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/CHACHA20_POLY1305") ) {
        CF_CHECK_GTE(op.ciphertext.GetSize(), crypto_aead_chacha20poly1305_IETF_ABYTES);

        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_chacha20poly1305_IETF_KEYBYTES);

        out = util::malloc(op.cleartextSize);

        unsigned long long cleartext_len;

        CF_CHECK_EQ(crypto_aead_chacha20poly1305_ietf_decrypt(
                out,
                &cleartext_len,
                NULL,
                op.ciphertext.GetPtr(),
                op.ciphertext.GetSize(),
                (unsigned char*)0x12,
                0,
                op.cipher.iv.GetPtr(),
                op.cipher.key.GetPtr()), 0);

        ret = component::Cleartext(out, cleartext_len);
    } else if ( op.cipher.cipherType.Get() == ID("Cryptofuzz/Cipher/XCHACHA20_POLY1305") ) {
        CF_CHECK_GTE(op.ciphertext.GetSize(), crypto_aead_xchacha20poly1305_IETF_ABYTES);

        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());
        CF_CHECK_EQ(op.cipher.iv.GetSize(), crypto_aead_xchacha20poly1305_IETF_NPUBBYTES);
        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_aead_xchacha20poly1305_IETF_KEYBYTES);

        out = util::malloc(op.cleartextSize);

        unsigned long long cleartext_len;

        CF_CHECK_EQ(crypto_aead_xchacha20poly1305_ietf_decrypt(
                out,
                &cleartext_len,
                NULL,
                op.ciphertext.GetPtr(),
                op.ciphertext.GetSize(),
                (unsigned char*)0x12,
                0,
                op.cipher.iv.GetPtr(),
                op.cipher.key.GetPtr()), 0);

        ret = component::Cleartext(out, cleartext_len);
    }

end:
    util::free(out);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
