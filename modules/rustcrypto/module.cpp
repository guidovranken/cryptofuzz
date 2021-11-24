#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int rustcrypto_hashes_hash(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
            const uint64_t algorithm,
            uint8_t* out);
    int rustcrypto_hmac(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
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
    int rustcrypto_bigint_bignumcalc(
            uint64_t op,
            uint8_t* bn0_bytes,
            uint8_t* bn1_bytes,
            uint8_t* bn2_bytes,
            uint8_t* result);
    int rustcrypto_cmac(
            const uint8_t* input_bytes, const size_t input_size,
            const size_t* parts_bytes, const size_t parts_size,
            const uint8_t* key_bytes, const size_t key_size,
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

std::optional<component::MAC> rustcrypto::OpHMAC(operation::HMAC& op) {
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
        const auto size = rustcrypto_hmac(
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                parts.data(), parts.size(),
                op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                op.digestType.Get(),
                out);
        CF_CHECK_GTE(size, 0);
        ret = component::MAC(out, size);
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

    {
        const auto size = rustcrypto_cmac(
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                parts.data(), parts.size(),
                op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                out);
        CF_CHECK_GTE(size, 0);
        ret = component::MAC(out, size);
    }

end:
    return ret;
}

std::optional<component::Bignum> rustcrypto::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    if ( op.modulo == std::nullopt ) {
        return ret;
    } else if ( op.modulo->ToTrimmedString() != "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
        return ret;
    }

    uint8_t result[32] = {0};
    std::optional<std::vector<uint8_t>> bn0, bn1, bn2;

    CF_CHECK_NE(bn0 = util::DecToBin(op.bn0.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(bn1 = util::DecToBin(op.bn1.ToTrimmedString(), 32), std::nullopt);
    CF_CHECK_NE(bn2 = util::DecToBin(op.bn2.ToTrimmedString(), 32), std::nullopt);

    {
        const auto res = rustcrypto_bigint_bignumcalc(
                op.calcOp.Get(),
                bn0->data(),
                bn1->data(),
                bn2->data(),
                result
        );

        CF_CHECK_EQ(res, 0);

        ret = util::BinToDec(result, sizeof(result));
    }

end:
    return ret;
}

bool rustcrypto::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
