#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace module {

Boost::Boost(void) :
    Module("Boost") { }

std::optional<component::Digest> Boost::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            {
                boost::uuids::detail::sha1 sha1;
                sha1.process_bytes(op.cleartext.GetPtr(), op.cleartext.GetSize());
                unsigned int out[5];
                sha1.get_digest(out);
                uint8_t out2[20];

                memcpy(out2, out, sizeof(out2));
                for (size_t i = 0; i < 20; i += 4) {
                    uint8_t tmp;

                    tmp = out2[i+0];
                    out2[i+0] = out2[i+3];
                    out2[i+3] = tmp;

                    tmp = out2[i+1];
                    out2[i+1] = out2[i+2];
                    out2[i+2] = tmp;
                }

                ret = component::Digest(out2, 20);
            }
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
