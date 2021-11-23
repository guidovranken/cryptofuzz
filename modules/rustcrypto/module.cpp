#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int rustcrypto_hashes_hash(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_hkdf(
            const uint8_t* password_bytes, const size_t password_size,
            const uint8_t* salt_bytes, const size_t salt_size,
            const uint8_t* info_bytes, const size_t info_size,
            const uint64_t keysize,
            const uint64_t algorithm,
            uint8_t* out);
}

namespace cryptofuzz {
namespace module {

rustcrypto::rustcrypto(void) :
    Module("RustCrypto") { }

std::optional<component::Digest> rustcrypto::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint8_t out[64];

    std::vector<size_t> parts;
    {
        const auto _parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : _parts) {
            parts.push_back(part.second);
        }
    }

    {
        const auto size = rustcrypto_hashes_hash(
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                parts.data(), parts.size(),
                op.digestType.Get(),
                out);
        CF_CHECK_GTE(size, 0);
        ret = component::Digest(out, size);
    }

end:
    return ret;
}

std::optional<component::Key> rustcrypto::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(rustcrypto_hkdf(
                op.password.GetPtr(), op.password.GetSize(),
                op.salt.GetPtr(), op.salt.GetSize(),
                op.info.GetPtr(), op.info.GetSize(),
                op.keySize,
                op.digestType.Get(),
                out), 0);

    ret = component::Key(out, op.keySize);
end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
