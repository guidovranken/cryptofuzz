#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int k256_ecc_privatetopublic(const uint8_t sk_bytes[32], uint8_t pk_bytes[65]);
    int k256_ecdsa_verify(const uint8_t msg_bytes[32], const uint8_t sig_bytes[34], const uint8_t pk_bytes[65]);
    int k256_ecdsa_sign(const uint8_t msg_bytes[32], const uint8_t sk_bytes[32], uint8_t sig_bytes[32]);
    int k256_validate_pubkey(const uint8_t pk_bytes[65]);
}

namespace cryptofuzz {
namespace module {

k256::k256(void) :
    Module("k256") { }

std::optional<component::ECC_PublicKey> k256::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    uint8_t pk_bytes[65];
    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);
    CF_CHECK_NE(k256_ecc_privatetopublic(sk_bytes->data(), pk_bytes), 0);
    ret = { util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32) };
end:
    return ret;
}

std::optional<bool> k256::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    uint8_t pk_bytes[65];
    pk_bytes[0] = 0x04;
    const auto x_bytes = util::DecToBin(op.pub.first.ToTrimmedString(), 32);
    const auto y_bytes = util::DecToBin(op.pub.second.ToTrimmedString(), 32);
    CF_CHECK_NE(x_bytes, std::nullopt);
    CF_CHECK_NE(y_bytes, std::nullopt);
    memcpy(pk_bytes + 1, x_bytes->data(), 32);
    memcpy(pk_bytes + 1 + 32, y_bytes->data(), 32);
    ret = k256_validate_pubkey(pk_bytes);
end:
    return ret;
}

std::optional<component::ECDSA_Signature> k256::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    if ( !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return ret;
    }
    if ( op.cleartext.GetSize() != 32 ) {
        return ret;
    }
    if ( op.UseRFC6979Nonce() == false ) {
        return ret;
    }

    uint8_t sig_bytes[64];
    uint8_t pk_bytes[65];
    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);

    CF_CHECK_NE(k256_ecc_privatetopublic(sk_bytes->data(), pk_bytes), 0);
    CF_CHECK_NE(k256_ecdsa_sign(op.cleartext.GetPtr(), sk_bytes->data(), sig_bytes), 0);
    CF_ASSERT(k256_ecdsa_verify(op.cleartext.GetPtr(), sig_bytes, pk_bytes) != 0, "Cannot verify generated signature");

    ret = component::ECDSA_Signature(
        {util::BinToDec(sig_bytes, 32), util::BinToDec(sig_bytes + 32, 32)},
        {util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32)}
    );

end:
    return ret;
}

std::optional<bool> k256::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    if ( !op.digestType.Is(CF_DIGEST("SHA256")) ) {
        return ret;
    }
    if ( op.cleartext.GetSize() != 32 ) {
        return ret;
    }
    const auto CT = op.cleartext;
    uint8_t pk_bytes[65];
    uint8_t sig_bytes[64];

    /* PK */
    pk_bytes[0] = 0x04;
    {
        const auto x_bytes = util::DecToBin(op.signature.pub.first.ToTrimmedString(), 32);
        const auto y_bytes = util::DecToBin(op.signature.pub.second.ToTrimmedString(), 32);
        CF_CHECK_NE(x_bytes, std::nullopt);
        CF_CHECK_NE(y_bytes, std::nullopt);
        memcpy(pk_bytes + 1, x_bytes->data(), 32);
        memcpy(pk_bytes + 1 + 32, y_bytes->data(), 32);
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

    ret = k256_ecdsa_verify(CT.GetPtr(), sig_bytes, pk_bytes);

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
