#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
    #include "Whirlpool.c"
}

namespace cryptofuzz {
namespace module {

PublicDomain::PublicDomain(void) :
    Module("Public Domain") { }

std::optional<component::Digest> PublicDomain::WHIRLPOOL(operation::Digest& op, Datasource& ds) const {
    std::optional<component::Digest> ret = std::nullopt;

    util::Multipart parts;
    struct NESSIEstruct nessie;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        NESSIEinit(&nessie);
    }

    /* Process */
    for (const auto& part : parts) {
        NESSIEadd(part.first, part.second * 8, &nessie);
    }

    /* Finalize */
    {
        uint8_t result[64];
        NESSIEfinalize(&nessie, result);
        ret = component::Digest(result, sizeof(result));
    }

    return ret;
}

std::optional<component::Digest> PublicDomain::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case ID("Cryptofuzz/Digest/WHIRLPOOL"):
            {
                return WHIRLPOOL(op, ds);
            }
            break;
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
