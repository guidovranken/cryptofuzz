#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int rustcrypto_hashes_hash(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
            const uint8_t* resets_bytes, const size_t resets_size,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_hmac(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
            const uint8_t* resets_bytes, const size_t resets_size,
            const uint8_t* key_bytes, const size_t key_size,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_hkdf(
            const uint8_t* password_bytes, const size_t password_size,
            const uint8_t* salt_bytes, const size_t salt_size,
            const uint8_t* info_bytes, const size_t info_size,
            const uint64_t keysize,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_scrypt(
            const uint8_t* password_bytes, const size_t password_size,
            const uint8_t* salt_bytes, const size_t salt_size,
            const uint8_t N,
            const uint32_t r,
            const uint32_t p,
            const uint64_t keysize,
            uint8_t* out);
    int rustcrypto_pbkdf2(
            const uint8_t* password_bytes, const size_t password_size,
            const uint8_t* salt_bytes, const size_t salt_size,
            const uint32_t iterations,
            const uint64_t keysize,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_bcrypt(
            const uint8_t* password_bytes, const size_t password_size,
            const uint8_t* salt_bytes, const size_t salt_size,
            const uint32_t iterations,
            const uint64_t keysize,
            uint8_t* out);
    int rustcrypto_argon2(
            const uint8_t* password_bytes, const size_t password_size,
            const uint8_t* salt_bytes, const size_t salt_size,
            const uint8_t algorithm,
            const uint8_t threads,
            const uint32_t memory,
            const uint32_t iterations,
            const uint64_t keysize,
            uint8_t* out);
    int rustcrypto_symmetric_encrypt(
            const uint8_t* input_bytes, const size_t input_size,
            const uint8_t* key_bytes, const size_t key_size,
            const uint8_t* iv_bytes, const size_t iv_size,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_symmetric_decrypt(
            const uint8_t* input_bytes, const size_t input_size,
            const uint8_t* key_bytes, const size_t key_size,
            const uint8_t* iv_bytes, const size_t iv_size,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_bigint_bignumcalc(
            uint64_t op,
            uint8_t* bn0_bytes,
            uint8_t* bn1_bytes,
            uint8_t* bn2_bytes,
            uint8_t modifier,
            uint8_t* result);
    int rustcrypto_cmac(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
            const uint8_t* resets_bytes, const size_t resets_size,
            const uint8_t* key_bytes, const size_t key_size,
            uint8_t* out);
    int rustcrypto_ecc_privatetopublic(
            uint64_t curve,
            const uint8_t sk_bytes[32],
            uint8_t pk_bytes[65]);
    int rustcrypto_validate_pubkey(
            uint64_t curve,
            const uint8_t pk_bytes[65]);
    int rustcrypto_ecdsa_sign(
            uint64_t curve,
            const uint8_t msg_bytes[32],
            const uint8_t sk_bytes[32],
            uint8_t sig_bytes[32]);
    int rustcrypto_ecc_point_add(
            uint64_t curve,
            const uint8_t a_bytes[65],
            const uint8_t b_bytes[65],
            uint8_t res_bytes[65]);
    int rustcrypto_ecc_point_mul(
            uint64_t curve,
            const uint8_t a_bytes[65],
            const uint8_t b_bytes[32],
            uint8_t res_bytes[65]);
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

    std::vector<uint8_t> resets;
    try {
        resets = ds.GetData(0);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    {
        const auto size = rustcrypto_hashes_hash(
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                parts.data(), parts.size(),
                resets.data(), resets.size(),
                op.digestType.Get(),
                out);
        CF_CHECK_GTE(size, 0);
        ret = component::Digest(out, size);
    }

end:
    return ret;
}

std::optional<component::MAC> rustcrypto::OpHMAC(operation::HMAC& op) {
    (void)op;
    return std::nullopt;
    /*
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

    std::vector<uint8_t> resets;
    try {
        resets = ds.GetData(0);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    {
        const auto size = rustcrypto_hmac(
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                parts.data(), parts.size(),
                resets.data(), resets.size(),
                op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                op.digestType.Get(),
                out);
        CF_CHECK_GTE(size, 0);
        ret = component::MAC(out, size);
    }

end:
    return ret;
    */
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
    util::free(out);
    return ret;
}

std::optional<component::Key> rustcrypto::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(rustcrypto_scrypt(
                op.password.GetPtr(), op.password.GetSize(),
                op.salt.GetPtr(), op.salt.GetSize(),
                op.N >> 1,
                op.r,
                op.p,
                op.keySize,
                out), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> rustcrypto::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(rustcrypto_pbkdf2(
                op.password.GetPtr(), op.password.GetSize(),
                op.salt.GetPtr(), op.salt.GetSize(),
                op.iterations,
                op.keySize,
                op.digestType.Get(),
                out), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> rustcrypto::OpKDF_BCRYPT(operation::KDF_BCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("SHA512"));
    CF_CHECK_EQ(rustcrypto_bcrypt(
                op.secret.GetPtr(), op.secret.GetSize(),
                op.salt.GetPtr(), op.salt.GetSize(),
                op.iterations,
                op.keySize,
                out), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> rustcrypto::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(rustcrypto_argon2(
                op.password.GetPtr(), op.password.GetSize(),
                op.salt.GetPtr(), op.salt.GetSize(),
                op.type,
                op.threads,
                op.memory,
                op.iterations,
                op.keySize,
                out), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);
    return ret;
}

std::optional<component::MAC> rustcrypto::OpCMAC(operation::CMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    if ( !op.cipher.cipherType.Is(CF_CIPHER("AES_128_CBC")) ) {
        return ret;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint8_t out[64];

    std::vector<size_t> parts;
    {
        const auto _parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : _parts) {
            parts.push_back(part.second);
        }
    }

    std::vector<uint8_t> resets;
    try {
        resets = ds.GetData(0);
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    {
        const auto size = rustcrypto_cmac(
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                parts.data(), parts.size(),
                resets.data(), resets.size(),
                op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                out);
        CF_CHECK_GTE(size, 0);
        ret = component::MAC(out, size);
    }

end:
    return ret;
}
        
std::optional<component::Ciphertext> rustcrypto::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    uint8_t* out = util::malloc(op.cleartext.GetSize());

    const auto size = rustcrypto_symmetric_encrypt(
            op.cleartext.GetPtr(), op.cleartext.GetSize(),
            op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
            op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(),
            op.cipher.cipherType.Get(),
            out);
    CF_CHECK_GTE(size, 0);

    ret = component::Ciphertext(Buffer(out, size));

end:
    util::free(out);

    return ret;
}
        
std::optional<component::Cleartext> rustcrypto::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;

    uint8_t* out = util::malloc(op.ciphertext.GetSize());

    const auto size = rustcrypto_symmetric_decrypt(
            op.ciphertext.GetPtr(), op.ciphertext.GetSize(),
            op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
            op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(),
            op.cipher.cipherType.Get(),
            out);
    CF_CHECK_GTE(size, 0);

    ret = component::Cleartext(Buffer(out, size));

end:
    util::free(out);

    return ret;
}

std::optional<component::Bignum> rustcrypto::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.modulo == std::nullopt ) {
        return ret;
    } else if ( op.modulo->ToTrimmedString() != "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
        return ret;
    }

    uint8_t result[32] = {0};
    std::optional<std::vector<uint8_t>> bn0, bn1, bn2;
    uint8_t modifier = 0;

    CF_CHECK_NE(bn0 = util::DecToBin(op.bn0.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(bn1 = util::DecToBin(op.bn1.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(bn2 = util::DecToBin(op.bn2.ToTrimmedString(), 32), std::nullopt);

    try {
        modifier = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    {
        const auto res = rustcrypto_bigint_bignumcalc(
                op.calcOp.Get(),
                bn0->data(),
                bn1->data(),
                bn2->data(),
                modifier,
                result
        );

        CF_CHECK_EQ(res, 0);

        ret = util::BinToDec(result, sizeof(result));
    }

end:
    return ret;
}

std::optional<component::ECC_PublicKey> rustcrypto::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) && !op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        return ret;
    }
    uint8_t pk_bytes[65];
    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);
    CF_CHECK_EQ(rustcrypto_ecc_privatetopublic(op.curveType.Get(), sk_bytes->data(), pk_bytes), 0);
    ret = { util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32) };
end:
    return ret;
}

std::optional<bool> rustcrypto::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) && !op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
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
    ret = rustcrypto_validate_pubkey(op.curveType.Get(), pk_bytes) == 0;
end:
    return ret;
}

std::optional<component::ECDSA_Signature> rustcrypto::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) && !op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
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
    if ( op.priv.ToTrimmedString() == "115792089210356248762697446949407573529996955224135760342422259061068512044368" ) {
        return ret;
    }

    uint8_t sig_bytes[64];
    uint8_t pk_bytes[65];
    const auto sk_bytes = util::DecToBin(op.priv.ToTrimmedString(), 32);
    CF_CHECK_NE(sk_bytes, std::nullopt);

    CF_CHECK_EQ(rustcrypto_ecc_privatetopublic(op.curveType.Get(), sk_bytes->data(), pk_bytes), 0);
    CF_CHECK_EQ(rustcrypto_ecdsa_sign(op.curveType.Get(), op.cleartext.GetPtr(), sk_bytes->data(), sig_bytes), 0);
    /* TODO */ //CF_ASSERT(rustcrypto_ecdsa_verify(op.cleartext.GetPtr(), sig_bytes, pk_bytes) == true, "Cannot verify generated signature");

    ret = component::ECDSA_Signature(
        {util::BinToDec(sig_bytes, 32), util::BinToDec(sig_bytes + 32, 32)},
        {util::BinToDec(pk_bytes + 1, 32), util::BinToDec(pk_bytes + 1 + 32, 32)}
    );

end:
    return ret;
}

std::optional<component::ECC_Point> rustcrypto::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) && !op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        return ret;
    }

    uint8_t a_bytes[65], b_bytes[65], res_bytes[65];

    {
        a_bytes[0] = 0x04;
        const auto x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32);
        const auto y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32);
        CF_CHECK_NE(x_bytes, std::nullopt);
        CF_CHECK_NE(y_bytes, std::nullopt);
        memcpy(a_bytes + 1, x_bytes->data(), 32);
        memcpy(a_bytes + 1 + 32, y_bytes->data(), 32);
    }

    {
        b_bytes[0] = 0x04;
        const auto x_bytes = util::DecToBin(op.b.first.ToTrimmedString(), 32);
        const auto y_bytes = util::DecToBin(op.b.second.ToTrimmedString(), 32);
        CF_CHECK_NE(x_bytes, std::nullopt);
        CF_CHECK_NE(y_bytes, std::nullopt);
        memcpy(b_bytes + 1, x_bytes->data(), 32);
        memcpy(b_bytes + 1 + 32, y_bytes->data(), 32);
    }

    CF_CHECK_EQ(rustcrypto_ecc_point_add(op.curveType.Get(), a_bytes, b_bytes, res_bytes), 0);

    ret = { util::BinToDec(res_bytes + 1, 32), util::BinToDec(res_bytes + 1 + 32, 32) };

end:
    return ret;
}

std::optional<component::ECC_Point> rustcrypto::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) && !op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        return ret;
    }

    uint8_t a_bytes[65], b_bytes[32], res_bytes[65];

    {
        a_bytes[0] = 0x04;
        const auto x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32);
        const auto y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32);
        CF_CHECK_NE(x_bytes, std::nullopt);
        CF_CHECK_NE(y_bytes, std::nullopt);
        memcpy(a_bytes + 1, x_bytes->data(), 32);
        memcpy(a_bytes + 1 + 32, y_bytes->data(), 32);
    }

    {
        const auto bytes = util::DecToBin(op.b.ToTrimmedString(), 32);
        CF_CHECK_NE(bytes, std::nullopt);
        memcpy(b_bytes, bytes->data(), 32);
    }

    CF_CHECK_EQ(rustcrypto_ecc_point_mul(op.curveType.Get(), a_bytes, b_bytes, res_bytes), 0);

    ret = { util::BinToDec(res_bytes + 1, 32), util::BinToDec(res_bytes + 1 + 32, 32) };

end:
    return ret;
}

bool rustcrypto::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
