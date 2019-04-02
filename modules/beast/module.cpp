#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

namespace cryptofuzz {
namespace module {

Beast::Beast(void) :
    Module("Beast") { }

std::optional<component::Digest> Beast::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case ID("Cryptofuzz/Digest/SHA1"):
            {
                Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

                util::Multipart parts;
                boost::beast::detail::sha1_context ctx;

                /* Initialize */
                {
                    /* Does not return a value */
                    boost::beast::detail::init(ctx);
                    parts = util::ToParts(ds, op.cleartext);
                }

                /* Process */
                for (const auto& part : parts) {
                    /* Does not return a value */
                    boost::beast::detail::update(ctx, part.first, part.second);
                }

                /* Finalize */
                {
                    unsigned char out[20];
                    /* Does not return a value */
                    boost::beast::detail::finish(ctx, out);

                    ret = component::Digest(out, sizeof(out));
                }
            }
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
