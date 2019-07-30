#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>

extern "C" {
#include "groestl.h"
#include "jh.h"
#include "skein.h"
#include "hmac-keccak.h"
}

namespace cryptofuzz {
namespace module {

Monero::Monero(void) :
    Module("Monero") { }

std::optional<component::Digest> Monero::groestl(operation::Digest& op, Datasource& ds) const {
    (void)ds;

    unsigned char out[32];

    ::groestl(op.cleartext.GetPtr(), op.cleartext.GetSize() * 8, out);

    return component::Digest(out, sizeof(out));
}

std::optional<component::Digest> Monero::jh(operation::Digest& op, Datasource& ds, const size_t hashSize) const {
    (void)ds;

    unsigned char out[hashSize / 8];

    jh_hash(hashSize, op.cleartext.GetPtr(), op.cleartext.GetSize() * 8, out);

    return component::Digest(out, hashSize / 8);
}

std::optional<component::Digest> Monero::skein(operation::Digest& op, Datasource& ds, const size_t hashSize) const {
    (void)ds;

    unsigned char out[hashSize / 8];

    skein_hash(hashSize, op.cleartext.GetPtr(), op.cleartext.GetSize() * 8, out);

    return component::Digest(out, hashSize / 8);
}

std::optional<component::Digest> Monero::keccak256(operation::Digest& op, Datasource& ds) const {
    KECCAK_CTX ctx;
    util::Multipart parts;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        keccak_init(&ctx);
    }

    /* Process */
    for (const auto& part : parts) {
        keccak_update(&ctx, part.first, part.second);
    }

    /* Finalize */
    {
        uint8_t out[32];
        keccak_finish(&ctx, out);
        return component::Digest(out, sizeof(out));
    }
}

std::optional<component::Digest> Monero::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("GROESTL_256"):
            {
                return groestl(op, ds);
            }
            break;
        case CF_DIGEST("JH_224"):
            {
                return jh(op, ds, 224);
            }
            break;
        case CF_DIGEST("JH_256"):
            {
                return jh(op, ds, 256);
            }
            break;
        case CF_DIGEST("JH_384"):
            {
                return jh(op, ds, 384);
            }
            break;
        case CF_DIGEST("JH_512"):
            {
                return jh(op, ds, 512);
            }
            break;
        case CF_DIGEST("SKEIN_256"):
            {
                return skein(op, ds, 256);
            }
            break;
        case CF_DIGEST("SKEIN_512"):
            {
                return skein(op, ds, 512);
            }
            break;
        case CF_DIGEST("SKEIN_1024"):
            {
                return skein(op, ds, 1024);
            }
            break;
        case CF_DIGEST("KECCAK_256"):
            {
                return keccak256(op, ds);
            }
            break;
    }

    return ret;
}

std::optional<component::MAC> Monero::OpHMAC(operation::HMAC& op) {
    using fuzzing::datasource::ID;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::MAC> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("KECCAK_256"):
            {
                auto parts = util::ToParts(ds, op.cleartext);

                hmac_keccak_state S;

                /* Initialize */
                {
                    hmac_keccak_init(&S, op.cipher.key.GetPtr(), op.cipher.key.GetSize());
                }

                /* Process */
                for (const auto& part : parts) {
                    hmac_keccak_update(&S, part.first, part.second);
                }

                /* Finalize */
                {
                    uint8_t out[32];
                    hmac_keccak_finish(&S, out);
                    ret = component::Digest(out, sizeof(out));
                }
            }
            break;
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
