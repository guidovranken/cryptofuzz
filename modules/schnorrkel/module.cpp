#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int sr25519_verify(const uint8_t sig_bytes[64], const uint8_t pk_bytes[32], const uint8_t* msg, const unsigned long msg_length);
}

namespace cryptofuzz {
namespace module {

schnorrkel::schnorrkel(void) :
    Module("schnorrkel") { }

std::optional<bool> schnorrkel::OpSR25519_Verify(operation::SR25519_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    uint8_t sig_bytes[64];
    uint8_t pk_bytes[32];

    /* PK */
    {
        const auto x_bytes = util::DecToBin(op.signature.pub.ToTrimmedString(), 32);
        CF_CHECK_NE(x_bytes, std::nullopt);
        memcpy(pk_bytes, x_bytes->data(), 32);
    }

    /* Signature */
    {
        const auto r_bytes = util::DecToBin(op.signature.signature.first.ToTrimmedString(), 32);
        const auto s_bytes = util::DecToBin(op.signature.signature.second.ToTrimmedString(), 32);
        CF_CHECK_NE(r_bytes, std::nullopt);
        CF_CHECK_NE(s_bytes, std::nullopt);
        memcpy(sig_bytes, r_bytes->data(), 32);
        memcpy(sig_bytes + 32, s_bytes->data(), 32);
    }

    ret = sr25519_verify(sig_bytes, pk_bytes, op.cleartext.GetPtr(), op.cleartext.GetSize());

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
