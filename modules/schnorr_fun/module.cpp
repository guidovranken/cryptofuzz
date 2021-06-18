#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int schnorr_fun_schnorr_verify(uint8_t* msg_bytes, size_t msg_size, const uint8_t sig_bytes[64], const uint8_t pk_bytes[32]);
}

namespace cryptofuzz {
namespace module {

schnorr_fun::schnorr_fun(void) :
    Module("schnorr_fun") { }

std::optional<bool> schnorr_fun::OpSchnorr_Verify(operation::Schnorr_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    std::vector<uint8_t> CT;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
        CT = op.cleartext.Get();
    } else if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        CT = op.cleartext.SHA256().Get();
    } else {
        return ret;
    }

    uint8_t pk_bytes[32];
    uint8_t sig_bytes[64];

    {
        const auto x_bytes = util::DecToBin(op.signature.pub.first.ToTrimmedString(), 32);
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

    ret = schnorr_fun_schnorr_verify(CT.data(), CT.size(), sig_bytes, pk_bytes);

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
