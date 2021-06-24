#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    bool schnorr_fun_schnorr_verify(uint8_t* msg_bytes, size_t msg_size, const uint8_t sig_bytes[64], const uint8_t pk_bytes[32]);
    bool schnorr_fun_schnorr_sign(uint8_t* msg_bytes, size_t msg_size, const uint8_t priv_bytes[32], uint8_t sig_bytes[64], uint8_t pk_bytes[32]);
}

namespace cryptofuzz {
namespace module {

schnorr_fun::schnorr_fun(void) :
    Module("schnorr_fun") { }

std::optional<component::Schnorr_Signature> schnorr_fun::OpSchnorr_Sign(operation::Schnorr_Sign& op) {
    std::optional<component::Schnorr_Signature> ret = std::nullopt;
    std::vector<uint8_t> CT;

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    if ( op.UseBIP340Nonce() == false ) {
        return ret;
    }

    if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
        CT = op.cleartext.Get();
    } else if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        CT = op.cleartext.SHA256().Get();
    } else {
        return ret;
    }

    uint8_t priv_bytes[32];
    uint8_t sig_bytes[64];
    uint8_t pk_bytes[32];

    {
        const auto _priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
        CF_CHECK_NE(_priv_bytes, std::nullopt);
        memcpy(priv_bytes, _priv_bytes->data(), 32);
    }

    CF_CHECK_TRUE(schnorr_fun_schnorr_sign(CT.data(), CT.size(), priv_bytes, sig_bytes, pk_bytes));

    {
        util::MemorySanitizerUnpoison(sig_bytes, sizeof(sig_bytes));
        util::MemorySanitizerUnpoison(pk_bytes, sizeof(pk_bytes));

        ret = component::Schnorr_Signature(
                {util::BinToDec(sig_bytes, 32), util::BinToDec(sig_bytes + 32, 32)},
                {util::BinToDec(pk_bytes, 32), "0"}
                );
    }

end:
    return ret;
}

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

    {
        const bool r = schnorr_fun_schnorr_verify(CT.data(), CT.size(), sig_bytes, pk_bytes);
        util::MemorySanitizerUnpoison(&r, sizeof(r));

        ret = r;
    }

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
