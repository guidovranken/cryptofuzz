#include "module.h"
#include <monocypher.h>
#include <cryptofuzz/util.h>

namespace cryptofuzz {
namespace module {

Monocypher::Monocypher(void) :
    Module("Monocypher") {
}

std::optional<component::Digest> Monocypher::OpDigest(operation::Digest& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Digest> ret = std::nullopt;

    if ( op.digestType.Get() == CF_DIGEST("BLAKE2B512") ) {
        bool streaming = false;
        try {
            streaming = ds.Get<bool>();
        } catch ( ... ) { }

        if ( streaming == true ) {
            uint8_t out[64];
            util::Multipart parts = util::ToParts(ds, op.cleartext);
            crypto_blake2b_ctx ctx;

            /* noret */ crypto_blake2b_init(&ctx);
            for (const auto& part : parts) {
                /* noret */ crypto_blake2b_update(&ctx, part.first, part.second);
            }
            /* noret */ crypto_blake2b_final(&ctx, out);
            ret = component::Digest(out, sizeof(out));
        } else {
            uint8_t out[64];
            /* noret */ crypto_blake2b(out, op.cleartext.GetPtr(), op.cleartext.GetSize());
            ret = component::Digest(out, sizeof(out));
        }
    }

    return ret;
}

std::optional<component::Ciphertext> Monocypher::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    uint8_t* out = nullptr;

    if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20") ) {
#if 0
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);

        out = util::malloc(op.cleartext.GetSize());

        /* noret */ crypto_chacha20(
                out,
                op.cleartext.GetPtr(),
                op.cleartext.GetSize(),
                op.cipher.key.GetPtr(),
                op.cipher.iv.GetPtr());

        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
#endif
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("XCHACHA20_POLY1305") ) {
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 24);
        CF_CHECK_NE(op.tagSize, std::nullopt);
        CF_CHECK_EQ(*op.tagSize, 16);

        uint8_t tag[16];

        out = util::malloc(op.cleartext.GetSize());

        /* noret */ crypto_lock_aead(
                tag,
                out,
                op.cipher.key.GetPtr(),
                op.cipher.iv.GetPtr(),
                op.aad == std::nullopt ? nullptr : op.aad->GetPtr(),
                op.aad == std::nullopt ? 0 : op.aad->GetSize(),
                op.cleartext.GetPtr(),
                op.cleartext.GetSize());

        ret = component::Ciphertext(
                Buffer(out, op.cleartext.GetSize()),
                Buffer(tag, sizeof(tag)));
    }

end:
    util::free(out);
    return ret;
}

std::optional<component::Cleartext> Monocypher::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;
    uint8_t* out = nullptr;

    if ( op.cipher.cipherType.Get() == CF_CIPHER("CHACHA20") ) {
#if 0
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);

        out = util::malloc(op.ciphertext.GetSize());

        /* noret */ crypto_chacha20(
                out,
                op.ciphertext.GetPtr(),
                op.ciphertext.GetSize(),
                op.cipher.key.GetPtr(),
                op.cipher.iv.GetPtr());

        ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
#endif
    } else if ( op.cipher.cipherType.Get() == CF_CIPHER("XCHACHA20_POLY1305") ) {
        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
        CF_CHECK_EQ(op.cipher.iv.GetSize(), 24);
        CF_CHECK_NE(op.tag, std::nullopt);
        CF_CHECK_EQ(op.tag->GetSize(), 16);

        out = util::malloc(op.ciphertext.GetSize());

        CF_CHECK_EQ(crypto_unlock_aead(
                out,
                op.cipher.key.GetPtr(),
                op.cipher.iv.GetPtr(),
                op.tag->GetPtr(),
                op.aad == std::nullopt ? nullptr : op.aad->GetPtr(),
                op.aad == std::nullopt ? 0 : op.aad->GetSize(),
                op.ciphertext.GetPtr(),
                op.ciphertext.GetSize()), 0);

        ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
    }

end:
    util::free(out);
    return ret;
}

#if 0
std::optional<component::Key> Monocypher::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;
    crypto_argon2_settings settings = {};

    if ( op.type != 1 ) {
        /* Not Argon2i */
        return ret;
    }
    settings.algorithm = CRYPTO_ARGON2_I;

    if ( op.threads != 1 ) {
        return ret;
    }
    settings.nb_lanes = op.threads;

    if ( op.memory < 8) {
        return ret;
    }
    settings.nb_blocks = op.memory;

    if ( op.iterations == 0 ) {
        /* iterations == 0 outputs uninitialized memory */
        return ret;
    }
    settings.nb_passes = op.iterations;

    uint8_t* out = util::malloc(op.keySize);
    settings.hash_size = op.keySize;

    uint8_t* work_area = util::malloc(op.memory * 1024);

    settings.salt_size = op.salt.GetSize();

    CF_NORET(crypto_argon2(
            out, work_area,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), settings));

    ret = component::Key(out, op.keySize);

    util::free(out);
    util::free(work_area);

    return ret;
}
#endif

} /* namespace module */
} /* namespace cryptofuzz */
