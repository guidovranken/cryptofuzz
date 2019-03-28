#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
#include "groestl.h"
#include "jh.h"
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

std::optional<component::Digest> Monero::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case ID("Cryptofuzz/Digest/GROESTL-256"):
            {
                return groestl(op, ds);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-224"):
            {
                return jh(op, ds, 224);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-256"):
            {
                return jh(op, ds, 256);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-384"):
            {
                return jh(op, ds, 384);
            }
            break;
        case ID("Cryptofuzz/Digest/JH-512"):
            {
                return jh(op, ds, 512);
            }
            break;
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
