#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
extern "C" {
int cryptofuzz_zig_digest(
        uint8_t* res_data,
        const uint8_t* cleartext_data,
        const uint32_t* parts_start,
        const uint32_t* parts_end,
        const uint32_t parts_size,
        const uint32_t digest);
void cryptofuzz_zig_hkdf(
        uint8_t* res_data, const size_t res_size,
        const uint8_t* password_data, const size_t password_size,
        const uint8_t* salt_data, const size_t salt_size,
        const uint8_t* info_data, const size_t info_size,
        const size_t digest);
int cryptofuzz_zig_pbkdf2_sha1(
        uint8_t* res_data, const size_t res_size,
        const uint8_t* password_data, const size_t password_size,
        const uint8_t* salt_data, const size_t salt_size,
        const uint32_t iterations);
int cryptofuzz_zig_scrypt(
        uint8_t* res_data, const size_t res_size,
        const uint8_t* password_data, const size_t password_size,
        const uint8_t* salt_data, const size_t salt_size,
        const uint32_t n,
        const uint32_t r,
        const uint32_t p);
size_t cryptofuzz_zig_bignumcalc(
        char* res_data, const size_t res_size,
        const char* a_data, const size_t a_size,
        const char* b_data, const size_t b_size,
        size_t operation);
}

namespace cryptofuzz {
namespace module {

Zig::Zig(void) :
    Module("Zig") { }

std::optional<component::Digest> Zig::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint32_t digest = -1;
    int outsize;
    uint8_t out[1024];
    util::Multipart parts;

    switch ( op.digestType.Get() ) {
        case    CF_DIGEST("MD5"):
            digest = 0;
            break;
        case    CF_DIGEST("SHA1"):
            digest = 1;
            break;
        case    CF_DIGEST("SHA224"):
            digest = 2;
            break;
        case    CF_DIGEST("SHA256"):
            digest = 3;
            break;
        case    CF_DIGEST("SHA384"):
            digest = 4;
            break;
        case    CF_DIGEST("SHA512"):
            digest = 5;
            break;
        case    CF_DIGEST("BLAKE2B128"):
            digest = 6;
            break;
        case    CF_DIGEST("BLAKE2B160"):
            digest = 7;
            break;
        case    CF_DIGEST("BLAKE2B256"):
            digest = 8;
            break;
        case    CF_DIGEST("BLAKE2B384"):
            digest = 9;
            break;
        case    CF_DIGEST("BLAKE2B512"):
            digest = 10;
            break;
        case    CF_DIGEST("BLAKE2S128"):
            digest = 11;
            break;
        case    CF_DIGEST("BLAKE2S160"):
            digest = 12;
            break;
        case    CF_DIGEST("BLAKE2S256"):
            digest = 13;
            break;
        default:
            return std::nullopt;
    }

    {
        parts = util::ToParts(ds, op.cleartext);

        std::vector<uint32_t> parts_start(parts.size());
        std::vector<uint32_t> parts_end(parts.size());

        size_t cur = 0;
        for (size_t i = 0; i < parts.size(); i++) {
            parts_start[i] = cur;
            parts_end[i] = cur + parts[i].second;
            cur += parts[i].second;
        }

        CF_CHECK_NE(outsize = cryptofuzz_zig_digest(
                    out,
                    op.cleartext.GetPtr(),
                    parts_start.data(),
                    parts_end.data(),
                    parts.size(),
                    digest), 1);
    }

end:
    ret = component::Digest(out, outsize);

    return ret;
}

std::optional<component::Key> Zig::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    size_t digest = 0;
    if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        if ( op.keySize > 255 * 32 ) {
            return std::nullopt;
        }
        digest = 0;
    } else if ( op.digestType.Is(CF_DIGEST("SHA512")) ) {
        if ( op.keySize > 255 * 64 ) {
            return std::nullopt;
        }
        digest = 1;
    } else {
        return std::nullopt;
    }

    uint8_t* out = util::malloc(op.keySize);

    cryptofuzz_zig_hkdf(
            out, op.keySize,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            op.info.GetPtr(), op.info.GetSize(),
            digest);

    ret = component::Key(out, op.keySize);

    util::free(out);

    return ret;
}

std::optional<component::Key> Zig::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    if ( !op.digestType.Is(CF_DIGEST("SHA1")) ) {
        return ret;
    }

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(cryptofuzz_zig_pbkdf2_sha1(
            out, op.keySize,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            op.iterations), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> Zig::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;

    const size_t N = op.N >> 1;

    if (N << 1 != op.N) {
        return ret;
    }

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(cryptofuzz_zig_scrypt(
            out, op.keySize,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            N, op.r, op.p), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Bignum> Zig::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint64_t operation = 0;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            operation = 0;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            operation = 1;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            operation = 2;
            break;
        case    CF_CALCOP("Div(A,B)"):
            operation = 3;
            break;
        case    CF_CALCOP("GCD(A,B)"):
            operation = 4;
            break;
        case    CF_CALCOP("Sqr(A)"):
            operation = 5;
            break;
        case    CF_CALCOP("Mod(A,B)"):
            operation = 6;
            break;
        case    CF_CALCOP("LShift1(A)"):
            operation = 7;
            break;
        case    CF_CALCOP("And(A,B)"):
            operation = 8;
            break;
        case    CF_CALCOP("Or(A,B)"):
            operation = 9;
            break;
        case    CF_CALCOP("Xor(A,B)"):
            operation = 10;
            break;
        case    CF_CALCOP("Neg(A)"):
            operation = 11;
            break;
        case    CF_CALCOP("Abs(A)"):
            operation = 12;
            break;
        case    CF_CALCOP("NumBits(A)"):
            operation = 13;
            break;
        case    CF_CALCOP("RShift(A,B)"):
            operation = 14;
            break;
        case    CF_CALCOP("Exp(A,B)"):
            operation = 15;
            break;
        default:
            return std::nullopt;
    }

    char res[8192];
    const auto bn0 = op.bn0.ToTrimmedString();
    const auto bn1 = op.bn1.ToTrimmedString();

    memset(res, 0, sizeof(res));
    CF_CHECK_EQ(cryptofuzz_zig_bignumcalc(
            res, sizeof(res),
            bn0.c_str(), bn0.size(),
            bn1.c_str(), bn1.size(),
            operation), 0);

    ret = std::string(res); 
end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
