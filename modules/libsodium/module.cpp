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

std::optional<component::Digest> libsodium::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Digest> ret = std::nullopt;

    if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA256") ) {
        uint8_t out[crypto_hash_sha256_BYTES];

        /* TODO return value */
        crypto_hash_sha256(out, op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha256_BYTES);
    } else if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA512") ) {
        uint8_t out[crypto_hash_sha512_BYTES];

        /* TODO return value */
        crypto_hash_sha512(out, op.cleartext.GetPtr(), op.cleartext.GetSize());

        ret = component::Digest(out, crypto_hash_sha512_BYTES);
    }

    return ret;
}

std::optional<component::MAC> libsodium::OpHMAC(operation::HMAC& op) {
    using fuzzing::datasource::ID;

    std::optional<component::MAC> ret = std::nullopt;

    if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA256") ) {
        uint8_t out[crypto_auth_hmacsha256_BYTES];

        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_auth_hmacsha256_KEYBYTES);

        /* TODO return value */
        crypto_auth_hmacsha256(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr());

        ret = component::MAC(out, crypto_auth_hmacsha256_BYTES);
    } else if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA512") ) {
        uint8_t out[crypto_auth_hmacsha512_BYTES];

        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_auth_hmacsha256_KEYBYTES);

        /* TODO return value */
        crypto_auth_hmacsha512(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr());

        ret = component::MAC(out, crypto_auth_hmacsha512_BYTES);
    } else if ( op.digestType.Get() == ID("Cryptofuzz/Digest/SHA512-256") ) {
        uint8_t out[crypto_auth_hmacsha512256_BYTES];

        CF_CHECK_EQ(op.cipher.key.GetSize(), crypto_auth_hmacsha512256_KEYBYTES);

        /* TODO return value */
        crypto_auth_hmacsha512256(out, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr());

        ret = component::MAC(out, crypto_auth_hmacsha512256_BYTES);
    }

end:
    return ret;
}

std::optional<component::Ciphertext> libsodium::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Ciphertext> ret = std::nullopt;

    uint8_t* out = (uint8_t*)malloc(op.ciphertextSize);

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
    free(out);

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

        out = (uint8_t*)malloc(op.cleartextSize);

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

        out = (uint8_t*)malloc(op.cleartextSize);

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

        out = (uint8_t*)malloc(op.cleartextSize);

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

        out = (uint8_t*)malloc(op.cleartextSize);

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
    free(out);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
