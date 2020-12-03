#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int ecc_privatetopublic(const uint8_t sk_bytes[32], uint8_t pk_bytes[65]);
    int ecdsa_verify(const uint8_t msg_bytes[32], const uint8_t sig_bytes[34], const uint8_t pk_bytes[65]);
    int ecdsa_sign(const uint8_t msg_bytes[32], const uint8_t sk_bytes[32], uint8_t sig_bytes[32]);
    int validate_pubkey(const uint8_t pk_bytes[65]);
}

namespace cryptofuzz {
namespace module {

rust_libsecp256k1::rust_libsecp256k1(void) :
    Module("rust_libsecp256k1") { }

std::optional<component::ECC_PublicKey> rust_libsecp256k1::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    uint8_t pk_bytes[65];
    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);
    CF_CHECK_NE(ecc_privatetopublic(sk_bytes->data(), pk_bytes), 0);
    ret = { util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32) };
end:
    return ret;
}

std::optional<bool> rust_libsecp256k1::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    uint8_t pk_bytes[65];
    pk_bytes[0] = 0x04;
    const auto x_bytes = util::DecToBin(op.pub.first.ToTrimmedString(), 32);
    const auto y_bytes = util::DecToBin(op.pub.second.ToTrimmedString(), 32);
    CF_CHECK_NE(x_bytes, std::nullopt);
    CF_CHECK_NE(y_bytes, std::nullopt);
    memcpy(pk_bytes + 1, x_bytes->data(), 32);
    memcpy(pk_bytes + 1 + 32, y_bytes->data(), 32);
    ret = validate_pubkey(pk_bytes);
end:
    return ret;
}

std::optional<component::ECDSA_Signature> rust_libsecp256k1::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    const uint8_t order[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
    if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
        return ret;
    }
    if ( op.cleartext.GetSize() != 32 ) {
        return ret;
    }
    if ( op.UseRFC6979Nonce() == false ) {
        return ret;
    }
    /* Pending fix for https://github.com/paritytech/libsecp256k1/issues/62 */
    if ( !memcmp(op.cleartext.GetPtr(), order, 32) ) {
        return ret;
    }

    uint8_t sig_bytes[64];
    uint8_t pk_bytes[65];
    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);

    CF_CHECK_NE(ecc_privatetopublic(sk_bytes->data(), pk_bytes), 0);
    CF_CHECK_NE(ecdsa_sign(op.cleartext.GetPtr(), sk_bytes->data(), sig_bytes), 0);

    ret = component::ECDSA_Signature(
        {util::BinToDec(sig_bytes, 32), util::BinToDec(sig_bytes + 32, 32)},
        {util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32)}
    );

end:
    return ret;
}

std::optional<bool> rust_libsecp256k1::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
        return ret;
    }
    if ( op.cleartext.GetSize() != 32 ) {
        return ret;
    }
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

    ret = ecdsa_verify(op.cleartext.GetPtr(), sig_bytes, pk_bytes);

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
