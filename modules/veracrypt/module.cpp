#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>

#include "kuznyechik.h"
#include "GostCipher.h"
#include "Streebog.h"
#include "Rmd160.h"
#include "t1ha.h"
#include "Sha2.h"
#include "chacha256.h"
#include "Whirlpool.h"
#include "Twofish.h"
#include "Serpent.h"
#include "Aes.h"

namespace cryptofuzz {
namespace module {

Veracrypt::Veracrypt(void) :
    Module("Veracrypt") {

        if ( aes_init() != EXIT_SUCCESS ) {
            abort();
        }
}


std::optional<component::Ciphertext> Veracrypt::kuznyechik(operation::SymmetricEncrypt& op) const {
    std::optional<component::Ciphertext> ret = std::nullopt;
    uint8_t* out = nullptr;

    kuznyechik_kds kds;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tagSize, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());

        /* Does not return a value */
        kuznyechik_set_key(op.cipher.key.GetPtr(), &kds);

        out = (uint8_t*)malloc(op.ciphertextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.cleartext.GetSize(); i += 16) {
            /* Does not return a value */
            kuznyechik_encrypt_block(out + i, op.cleartext.GetPtr() + i, &kds);
        }
    }

    /* Finalize */
    {
        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
    }

end:
    free(out);

    return ret;
}

std::optional<component::Cleartext> Veracrypt::kuznyechik(operation::SymmetricDecrypt& op) const {
    std::optional<component::Cleartext> ret = std::nullopt;
    uint8_t* out = nullptr;

    kuznyechik_kds kds;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tag, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());

        /* Does not return a value */
        kuznyechik_set_key(op.cipher.key.GetPtr(), &kds);

        out = (uint8_t*)malloc(op.cleartextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.ciphertext.GetSize(); i += 16) {
            /* Does not return a value */
            kuznyechik_decrypt_block(out + i, op.ciphertext.GetPtr() + i, &kds);
        }
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, op.ciphertext.GetSize());
    }

end:
    free(out);

    return ret;
}

std::optional<component::Ciphertext> Veracrypt::GOST_28147_89(operation::SymmetricEncrypt& op) const {
    std::optional<component::Ciphertext> ret = std::nullopt;
    uint8_t* out = nullptr;

    gost_kds kds;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tagSize, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());

        /* Does not return a value */
        gost_set_key(op.cipher.key.GetPtr(), &kds, 0);

        out = (uint8_t*)malloc(op.ciphertextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.cleartext.GetSize(); i += 16) {
            /* Does not return a value */
            gost_encrypt(op.cleartext.GetPtr() + i, out + i, &kds, 1);
        }
    }

    /* Finalize */
    {
        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
    }

end:
    free(out);

    return ret;
}

std::optional<component::Cleartext> Veracrypt::GOST_28147_89(operation::SymmetricDecrypt& op) const {
    std::optional<component::Cleartext> ret = std::nullopt;
    uint8_t* out = nullptr;

    gost_kds kds;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tag, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());

        /* Does not return a value */
        gost_set_key(op.cipher.key.GetPtr(), &kds, 0);

        out = (uint8_t*)malloc(op.cleartextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.ciphertext.GetSize(); i += 16) {
            /* Does not return a value */
            gost_decrypt(op.ciphertext.GetPtr() + i, out + i, &kds, 1);
        }
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, op.ciphertext.GetSize());
    }

end:
    free(out);

    return ret;
}

std::optional<component::Ciphertext> Veracrypt::twofish(operation::SymmetricEncrypt& op) const {
    std::optional<component::Ciphertext> ret = std::nullopt;
    uint8_t* out = nullptr;

    TwofishInstance instance;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tagSize, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());

        /* Does not return a value */
        twofish_set_key(&instance, (const unsigned int*)op.cipher.key.GetPtr());

        out = (uint8_t*)malloc(op.ciphertextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.cleartext.GetSize(); i += 16) {
            /* Does not return a value */
            twofish_encrypt(&instance, (const unsigned int*)(op.cleartext.GetPtr() + i), (unsigned int*)(out + i));
        }
    }

    /* Finalize */
    {
        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
    }

end:
    free(out);

    return ret;
}

std::optional<component::Cleartext> Veracrypt::twofish(operation::SymmetricDecrypt& op) const {
    std::optional<component::Cleartext> ret = std::nullopt;
    uint8_t* out = nullptr;

    TwofishInstance instance;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tag, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());

        /* Does not return a value */
        twofish_set_key(&instance, (const unsigned int*)op.cipher.key.GetPtr());

        out = (uint8_t*)malloc(op.cleartextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.ciphertext.GetSize(); i += 16) {
            /* Does not return a value */
            twofish_decrypt(&instance, (const unsigned int*)(op.ciphertext.GetPtr() + i), (unsigned int*)(out + i));
        }
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, op.ciphertext.GetSize());
    }

end:
    free(out);

    return ret;
}

std::optional<component::Ciphertext> Veracrypt::serpent(operation::SymmetricEncrypt& op) const {
    std::optional<component::Ciphertext> ret = std::nullopt;
    uint8_t* out = nullptr;

    uint8_t ks[140*4];

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tagSize, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (16 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());

        /* Does not return a value */
        serpent_set_key(op.cipher.key.GetPtr(), ks);

        out = (uint8_t*)malloc(op.ciphertextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.cleartext.GetSize(); i += 16) {
            /* Does not return a value */
            serpent_encrypt(op.cleartext.GetPtr() + i, out + i, ks);
        }
    }

    /* Finalize */
    {
        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
    }

end:
    free(out);

    return ret;
}

std::optional<component::Cleartext> Veracrypt::serpent(operation::SymmetricDecrypt& op) const {
    std::optional<component::Cleartext> ret = std::nullopt;
    uint8_t* out = nullptr;

    uint8_t ks[140*4];

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tag, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());

        /* Does not return a value */
        serpent_set_key(op.cipher.key.GetPtr(), ks);

        out = (uint8_t*)malloc(op.cleartextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.ciphertext.GetSize(); i += 16) {
            /* Does not return a value */
            serpent_decrypt(op.ciphertext.GetPtr() + i, out + i, ks);
        }
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, op.ciphertext.GetSize());
    }

end:
    free(out);

    return ret;
}

std::optional<component::Ciphertext> Veracrypt::aes(operation::SymmetricEncrypt& op) const {
    std::optional<component::Ciphertext> ret = std::nullopt;
    uint8_t* out = nullptr;

    aes_encrypt_ctx cx;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tagSize, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (16 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());

        CF_CHECK_EQ(aes_encrypt_key256(op.cipher.key.GetPtr(), &cx), EXIT_SUCCESS);

        out = (uint8_t*)malloc(op.ciphertextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.cleartext.GetSize(); i += 16) {
            CF_CHECK_EQ(aes_encrypt(op.cleartext.GetPtr() + i, out + i, &cx), EXIT_SUCCESS);
        }
    }

    /* Finalize */
    {
        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
    }

end:
    free(out);

    return ret;
}

std::optional<component::Cleartext> Veracrypt::aes(operation::SymmetricDecrypt& op) const {
    std::optional<component::Cleartext> ret = std::nullopt;
    uint8_t* out = nullptr;

    aes_decrypt_ctx cx;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tag, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Input size must be a multiple of 16 */
        CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
        CF_CHECK_GTE(op.cleartextSize, op.ciphertext.GetSize());

        CF_CHECK_EQ(aes_decrypt_key256(op.cipher.key.GetPtr(), &cx), EXIT_SUCCESS);

        out = (uint8_t*)malloc(op.cleartextSize);
    }

    /* Process */
    {
        for (size_t i = 0; i < op.ciphertext.GetSize(); i += 16) {
            CF_CHECK_EQ(aes_decrypt(op.ciphertext.GetPtr() + i, out + i, &cx), EXIT_SUCCESS);
        }
    }

    /* Finalize */
    {
        ret = component::Cleartext(out, op.ciphertext.GetSize());
    }

end:
    free(out);

    return ret;
}

std::optional<component::Ciphertext> Veracrypt::chacha20(operation::SymmetricEncrypt& op) const {
    std::optional<component::Ciphertext> ret = std::nullopt;
    uint8_t* out = nullptr;

    ChaCha256Ctx ctx;

    /* Initialize */
    {
        /* Not an AEAD cipher */
        CF_CHECK_EQ(op.tagSize, std::nullopt);
        CF_CHECK_EQ(op.aad, std::nullopt);

        /* Fixed key size (32 bytes) */
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);

        /* Fixed iv size (8 bytes) */
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);

        CF_CHECK_GTE(op.ciphertextSize, op.cleartext.GetSize());

        /* Does not return a value */
        ChaCha256Init(&ctx, op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), 256);

        out = (uint8_t*)malloc(op.ciphertextSize);
    }

    /* Process */
    {
        /* Does not return a value */
        ChaCha256Encrypt(&ctx, op.cleartext.GetPtr(), op.cleartext.GetSize(), out);
    }

    /* Finalize */
    {
        //ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
    }

end:
    free(out);

    return ret;
}

std::optional<component::Digest> Veracrypt::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Digest> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::Multipart parts;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("STREEBOG-256"):
        case CF_DIGEST("STREEBOG-512"):
            {
                STREEBOG_CTX ctx;

                /* Initialize */
                {
                    parts = util::ToParts(ds, op.cleartext);
                    if ( op.digestType.Get() == CF_DIGEST("STREEBOG-256") ) {
                        /* Does not return a value */
                        STREEBOG_init256(&ctx);
                    } else {
                        /* Does not return a value */
                        STREEBOG_init(&ctx);
                    }
                }

                /* Process */
                for (const auto& part : parts) {
                    /* Does not return a value */
                    STREEBOG_add(&ctx, part.first, part.second);
                }

                /* Finalize */
                {

                    if ( op.digestType.Get() == CF_DIGEST("STREEBOG-256") ) {
                        unsigned char out[32];
                        /* Does not return a value */
                        STREEBOG_finalize(&ctx, out);
                        ret = component::Digest(out, 32);
                    } else {
                        unsigned char out[64];
                        /* Does not return a value */
                        STREEBOG_finalize(&ctx, out);
                        ret = component::Digest(out, 64);
                    }
                }
            }
            break;
        case CF_DIGEST("RIPEMD160"):
            {
                RMD160Context ctx;

                /* Initialize */
                {
                    parts = util::ToParts(ds, op.cleartext);
                    /* Does not return a value */
                    RMD160Init(&ctx);
                }

                /* Process */
                for (const auto& part : parts) {
                    /* Does not return a value */
                    RMD160Update(&ctx, part.first, part.second);
                }

                /* Finalize */
                {
                    unsigned char out[20];
                    /* Does not return a value */
                    RMD160Final(out, &ctx);
                    ret = component::Digest(out, sizeof(out));
                }
            }
            break;
        case CF_DIGEST("T1HA-64"):
        case CF_DIGEST("T1HA-128"):
            {
                t1ha_context_t ctx;

                /* Initialize */
                {
                    /* TODO variable seeds */
                    /* Does not return a value */
                    t1ha2_init(&ctx, 111, 999);
                    parts = util::ToParts(ds, op.cleartext);
                }

                /* Process */
                for (const auto& part : parts) {
                    /* Does not return a value */
                    t1ha2_update(&ctx, part.first, part.second);
                }

                /* Finalize */
                {
                    if ( op.digestType.Get() == CF_DIGEST("T1HA-64") ) {
                        const uint64_t res = t1ha2_final(&ctx, nullptr);

                        /* TODO endianness */
                        ret = component::Digest((const uint8_t*)&res, sizeof(res));
                    } else {
                        uint64_t res2;
                        const uint64_t res = t1ha2_final(&ctx, &res2);

                        unsigned char digest[sizeof(res) + sizeof(res2)];

                        /* TODO endianness */
                        memcpy(digest, &res, sizeof(res));
                        memcpy(digest + sizeof(res), &res2, sizeof(res2));

                        ret = component::Digest(digest, sizeof(digest));
                    }
                }
            }
            break;
        case CF_DIGEST("SHA256"):
            {
                sha256_ctx ctx;

                /* Initialize */
                {
                    /* Does not return a value */
                    sha256_begin(&ctx);
                    parts = util::ToParts(ds, op.cleartext);
                }

                /* Process */
                {
                    for (const auto& part : parts) {
                        /* Does not return a value */
                        sha256_hash(part.first, part.second, &ctx);
                    }
                }

                /* Finalize */
                {
                    uint8_t out[32];
                    /* Does not return a value */
                    sha256_end(out, &ctx);
                    ret = component::Digest(out, sizeof(out));
                }
            }
            break;
        case CF_DIGEST("SHA512"):
            {
                sha512_ctx ctx;

                /* Initialize */
                {
                    /* Does not return a value */
                    sha512_begin(&ctx);
                    parts = util::ToParts(ds, op.cleartext);
                }

                /* Process */
                {
                    for (const auto& part : parts) {
                        /* Does not return a value */
                        sha512_hash(part.first, part.second, &ctx);
                    }
                }

                /* Finalize */
                {
                    uint8_t out[64];
                    /* Does not return a value */
                    sha512_end(out, &ctx);
                    ret = component::Digest(out, sizeof(out));
                }
            }
            break;
        case CF_DIGEST("WHIRLPOOL"):
            {
                WHIRLPOOL_CTX ctx;

                /* Initialize */
                {
                    /* Does not return a value */
                    WHIRLPOOL_init(&ctx);
                    parts = util::ToParts(ds, op.cleartext);
                }

                /* Process */
                {
                    for (const auto& part : parts) {
                        /* Does not return a value */
                        WHIRLPOOL_add(part.first, part.second, &ctx);
                    }
                }

                /* Finalize */
                {
                    uint8_t out[64];
                    /* Does not return a value */
                    WHIRLPOOL_finalize(&ctx, out);
                    ret = component::Digest(out, sizeof(out));
                }
            }
            break;
    }

    return ret;
}

std::optional<component::Ciphertext> Veracrypt::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Ciphertext> ret = std::nullopt;

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("KUZNYECHIK"):
            {
                return kuznyechik(op);
            }
            break;
        case    CF_CIPHER("GOST-28147-89"):
            {
                return GOST_28147_89(op);
            }
            break;
        case    CF_CIPHER("CHACHA20"):
            {
                return chacha20(op);
            }
            break;
        case    CF_CIPHER("TWOFISH"):
            {
                return twofish(op);
            }
            break;
        case    CF_CIPHER("SERPENT"):
            {
                return serpent(op);
            }
            break;
        case    CF_CIPHER("AES"):
            {
                return aes(op);
            }
            break;
    }

    return ret;
}

std::optional<component::Cleartext> Veracrypt::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Cleartext> ret = std::nullopt;

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("KUZNYECHIK"):
            {
                return kuznyechik(op);
            }
            break;
        case    CF_CIPHER("GOST-28147-89"):
            {
                return GOST_28147_89(op);
            }
            break;
        case    CF_CIPHER("TWOFISH"):
            {
                return twofish(op);
            }
            break;
        case    CF_CIPHER("SERPENT"):
            {
                return serpent(op);
            }
            break;
        case    CF_CIPHER("AES"):
            {
                return aes(op);
            }
            break;
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
