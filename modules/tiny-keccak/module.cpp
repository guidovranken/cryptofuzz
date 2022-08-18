#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    void cryptofuzz_tiny_keccak(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
            uint8_t* out);
}

namespace cryptofuzz {
namespace module {

tiny_keccak::tiny_keccak(void) :
    Module("tiny-keccak") { }

std::optional<component::Digest> tiny_keccak::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( !op.digestType.Is(CF_DIGEST("KECCAK_256")) ) {
        return ret;
    }
    uint8_t out[32];

    std::vector<size_t> parts;
    {
        const auto _parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : _parts) {
            parts.push_back(part.second);
        }
    }

    {
        CF_NORET(cryptofuzz_tiny_keccak(
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                parts.data(), parts.size(),
                out));
        ret = component::Digest(out, 32);
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
