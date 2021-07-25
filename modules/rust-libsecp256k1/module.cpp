#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    bool parity_libsecp256k1_ecc_privatetopublic(const uint8_t sk_bytes[32], uint8_t pk_bytes[65]);
    bool parity_libsecp256k1_ecdsa_verify(const uint8_t msg_bytes[32], const uint8_t sig_bytes[34], const uint8_t pk_bytes[65]);
    bool parity_libsecp256k1_ecdsa_sign(const uint8_t msg_bytes[32], const uint8_t sk_bytes[32], uint8_t sig_bytes[32]);
    bool parity_libsecp256k1_validate_pubkey(const uint8_t pk_bytes[65]);
    bool parity_libsecp256k1_ecdsa_recover(const uint8_t msg_bytes[32], const uint8_t sig_bytes[32], const uint8_t id, uint8_t pk_bytes[65]);
    bool parity_libsecp256k1_ecdh_derive(const uint8_t sk_bytes[32], const uint8_t pk_bytes[65], uint8_t shared_bytes[32]);
    bool parity_libsecp256k1_ecc_point_mul(const uint8_t scalar_bytes[32], const uint8_t point_bytes[65], uint8_t res_bytes[64]);
}

namespace cryptofuzz {
namespace module {

rust_libsecp256k1::rust_libsecp256k1(void) :
    Module("rust_libsecp256k1") { }

std::optional<component::ECC_PublicKey> rust_libsecp256k1::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    uint8_t pk_bytes[65];
    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);
    CF_CHECK_TRUE(parity_libsecp256k1_ecc_privatetopublic(sk_bytes->data(), pk_bytes));
    ret = { util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32) };
end:
    return ret;
}

std::optional<bool> rust_libsecp256k1::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
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
    ret = parity_libsecp256k1_validate_pubkey(pk_bytes);
end:
    return ret;
}

std::optional<component::ECDSA_Signature> rust_libsecp256k1::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    if ( op.UseRFC6979Nonce() == false ) {
        return ret;
    }

    Buffer CT;
    uint8_t sig_bytes[64];
    uint8_t pk_bytes[65];

    if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
        CT = op.cleartext.ECDSA_Pad(32);
    } else if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        CT = op.cleartext.SHA256();
    } else {
        return ret;
    }

    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);

    CF_CHECK_TRUE(parity_libsecp256k1_ecc_privatetopublic(sk_bytes->data(), pk_bytes));
    CF_CHECK_TRUE(parity_libsecp256k1_ecdsa_sign(CT.GetPtr(), sk_bytes->data(), sig_bytes));

    /* Pending fix for https://github.com/paritytech/libsecp256k1/issues/62 */
    {
        static const uint8_t order[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
        if ( !memcmp(CT.GetPtr(), order, 32) ) {
            return ret;
        }
    }

    ret = component::ECDSA_Signature(
        {util::BinToDec(sig_bytes, 32), util::BinToDec(sig_bytes + 32, 32)},
        {util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32)}
    );


end:
    return ret;
}

std::optional<bool> rust_libsecp256k1::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    Buffer CT;
    uint8_t pk_bytes[65];
    uint8_t sig_bytes[64];

    if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
        CT = op.cleartext.ECDSA_Pad(32);
    } else if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        CT = op.cleartext.SHA256();
    } else {
        return ret;
    }

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

    ret = parity_libsecp256k1_ecdsa_verify(CT.GetPtr(), sig_bytes, pk_bytes);

end:
    return ret;
}

std::optional<component::ECC_PublicKey> rust_libsecp256k1::OpECDSA_Recover(operation::ECDSA_Recover& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    uint8_t sig_bytes[64];
    uint8_t pk_bytes[65];
    Buffer CT;

    if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
        CT = op.cleartext.ECDSA_Pad(32);
    } else if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        CT = op.cleartext.SHA256();
    } else {
        return ret;
    }

    /* Signature */
    {
        const auto r_bytes = util::DecToBin(op.signature.first.ToTrimmedString(), 32);
        const auto s_bytes = util::DecToBin(op.signature.second.ToTrimmedString(), 32);
        CF_CHECK_NE(r_bytes, std::nullopt);
        CF_CHECK_NE(s_bytes, std::nullopt);
        memcpy(sig_bytes, r_bytes->data(), 32);
        memcpy(sig_bytes + 32, s_bytes->data(), 32);
    }

    CF_CHECK_TRUE(parity_libsecp256k1_ecdsa_recover(CT.GetPtr(), sig_bytes, op.id, pk_bytes));

    ret = { util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32) };

end:
    return ret;
}

std::optional<component::Secret> rust_libsecp256k1::OpECDH_Derive(operation::ECDH_Derive& op) {
    std::optional<component::Secret> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    uint8_t pk_bytes[65];
    uint8_t shared_bytes[32];

    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);

    {
        pk_bytes[0] = 0x04;
        const auto x_bytes = util::DecToBin(op.pub.first.ToTrimmedString(), 32);
        const auto y_bytes = util::DecToBin(op.pub.second.ToTrimmedString(), 32);
        CF_CHECK_NE(x_bytes, std::nullopt);
        CF_CHECK_NE(y_bytes, std::nullopt);
        memcpy(pk_bytes + 1, x_bytes->data(), 32);
        memcpy(pk_bytes + 1 + 32, y_bytes->data(), 32);
    }

    CF_CHECK_TRUE(parity_libsecp256k1_ecdh_derive(sk_bytes->data(), pk_bytes, shared_bytes));

    ret = component::Secret(Buffer(shared_bytes, 32));

end:
    return ret;
}

std::optional<component::ECC_Point> rust_libsecp256k1::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }

    uint8_t point_bytes[65];
    uint8_t res_bytes[64];

    const auto scalar_bytes = util::DecToBin(op.b.ToTrimmedString(), 32);
    CF_CHECK_NE(scalar_bytes, std::nullopt);

    {
        point_bytes[0] = 0x04;
        const auto x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32);
        const auto y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32);
        CF_CHECK_NE(x_bytes, std::nullopt);
        CF_CHECK_NE(y_bytes, std::nullopt);
        memcpy(point_bytes + 1, x_bytes->data(), 32);
        memcpy(point_bytes + 1 + 32, y_bytes->data(), 32);
    }

    CF_CHECK_TRUE(parity_libsecp256k1_ecc_point_mul(scalar_bytes->data(), point_bytes, res_bytes));

    ret = { util::BinToDec(res_bytes, 32), util::BinToDec(res_bytes + 32, 32) };

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
