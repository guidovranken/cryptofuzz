#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
extern "C" {
int cryptofuzz_zig_digest(
        uint8_t* res_data,
        const uint8_t* cleartext_data,
        const uint32_t* parts_start,
        const uint32_t* parts_end,
        const uint32_t parts_size,
        const uint32_t digest);
int cryptofuzz_zig_hmac(
        uint8_t* res_data,
        const uint8_t* key_data, const size_t key_size,
        const uint8_t* cleartext_data,
        const uint32_t* parts_start,
        const uint32_t* parts_end,
        const uint32_t parts_size,
        const uint32_t digest);
int cryptofuzz_zig_hkdf(
        uint8_t* res_data, const size_t res_size,
        const uint8_t* password_data, const size_t password_size,
        const uint8_t* salt_data, const size_t salt_size,
        const uint8_t* info_data, const size_t info_size,
        const size_t digest);
int cryptofuzz_zig_pbkdf2(
        uint8_t* res_data, const size_t res_size,
        const uint8_t* password_data, const size_t password_size,
        const uint8_t* salt_data, const size_t salt_size,
        const uint32_t iterations,
        const size_t digest);
int cryptofuzz_zig_scrypt(
        uint8_t* res_data, const size_t res_size,
        const uint8_t* password_data, const size_t password_size,
        const uint8_t* salt_data, const size_t salt_size,
        const uint32_t n,
        const uint32_t r,
        const uint32_t p);
int cryptofuzz_zig_argon2(
        uint8_t* res_data, const size_t res_size,
        const uint8_t* password_data, const size_t password_size,
        const uint8_t* salt_data, const size_t salt_size,
        const uint32_t iterations,
        const uint32_t memory,
        const uint8_t threads,
        const uint8_t mode);
size_t cryptofuzz_zig_ecdsa_verify(
        const uint32_t curve,
        const uint8_t* pub_bytes,
        const uint32_t pub_size,
        const uint8_t* msg_bytes,
        const uint32_t msg_size,
        const uint8_t* sig_bytes,
        const uint32_t sig_size);
size_t cryptofuzz_zig_ecc_validatepubkey(
        const uint32_t curve,
        const uint8_t* ax_bytes,
        const uint8_t* ay_bytes);
size_t cryptofuzz_zig_ecc_privatetopublic(
        const uint32_t curve,
        uint8_t* r,
        const uint8_t* priv_bytes);
size_t cryptofuzz_zig_ecc_point_add(
        const uint32_t curve,
        uint8_t* r,
        const uint8_t* ax_bytes,
        const uint8_t* ay_bytes,
        const uint8_t* bx_bytes,
        const uint8_t* by_bytes);
size_t cryptofuzz_zig_ecc_point_sub(
        const uint32_t curve,
        uint8_t* r,
        const uint8_t* ax_bytes,
        const uint8_t* ay_bytes,
        const uint8_t* bx_bytes,
        const uint8_t* by_bytes);
size_t cryptofuzz_zig_ecc_point_mul(
        const uint32_t curve,
        uint8_t* r,
        const uint8_t* ax_bytes,
        const uint8_t* ay_bytes,
        const uint8_t* b_bytes,
        const int32_t alt);
size_t cryptofuzz_zig_ecc_point_neg(
        const uint32_t curve,
        uint8_t* r,
        const uint8_t* ax_bytes,
        const uint8_t* ay_bytes);
size_t cryptofuzz_zig_ecc_point_dbl(
        const uint32_t curve,
        uint8_t* r,
        const uint8_t* ax_bytes,
        const uint8_t* ay_bytes);
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

namespace Zig_detail {
    std::optional<uint32_t> ToDigestId(const uint64_t digestType) {
        switch ( digestType ) {
            case    CF_DIGEST("MD5"):
                return 0;
            case    CF_DIGEST("SHA1"):
                return 1;
            case    CF_DIGEST("SHA224"):
                return 2;
            case    CF_DIGEST("SHA256"):
                return 3;
            case    CF_DIGEST("SHA384"):
                return 4;
            case    CF_DIGEST("SHA512"):
                return 5;
            case    CF_DIGEST("BLAKE2B128"):
                return 6;
            case    CF_DIGEST("BLAKE2B160"):
                return 7;
            case    CF_DIGEST("BLAKE2B256"):
                return 8;
            case    CF_DIGEST("BLAKE2B384"):
                return 9;
            case    CF_DIGEST("BLAKE2B512"):
                return 10;
            case    CF_DIGEST("BLAKE2S128"):
                return 11;
            case    CF_DIGEST("BLAKE2S160"):
                return 12;
            case    CF_DIGEST("BLAKE2S256"):
                return 13;
            case    CF_DIGEST("BLAKE3"):
                return 14;
            case    CF_DIGEST("SHA3-224"):
                return 15;
            case    CF_DIGEST("SHA3-256"):
                return 16;
            case    CF_DIGEST("SHA3-384"):
                return 17;
            case    CF_DIGEST("SHA3-512"):
                return 18;
            case    CF_DIGEST("KECCAK_256"):
                return 19;
            case    CF_DIGEST("KECCAK_512"):
                return 20;
            default:
                return std::nullopt;
        }
    }

    static component::ECC_Point To_Component_ECC_Point(const uint8_t* r, const size_t size) {
        const auto x = util::BinToDec(std::vector<uint8_t>(r + 1, r + 1 + size));
        auto y = util::BinToDec(std::vector<uint8_t>(r + 1 + size, r + 1 + size + size));

        if ( x == "0" && y == "1" ) {
            /* Zig encodes point at infinity as (0, 1); reencode as (0, 0) */
            y = "0";
        }

        return component::ECC_Point{x, y};
    }
}

std::optional<component::Digest> Zig::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<uint32_t> digest = std::nullopt;
    uint8_t out[1024];
    util::Multipart parts;

    CF_CHECK_NE(digest = Zig_detail::ToDigestId(op.digestType.Get()), std::nullopt);

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

        int outsize;
        CF_CHECK_NE(outsize = cryptofuzz_zig_digest(
                    out,
                    op.cleartext.GetPtr(),
                    parts_start.data(),
                    parts_end.data(),
                    parts.size(),
                    *digest), 1);
        ret = component::Digest(out, outsize);
    }

end:

    return ret;
}

std::optional<component::MAC> Zig::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<uint32_t> digest = std::nullopt;
    uint8_t out[1024];
    util::Multipart parts;

    CF_CHECK_NE(digest = Zig_detail::ToDigestId(op.digestType.Get()), std::nullopt);

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

        int outsize;
        CF_CHECK_NE(outsize = cryptofuzz_zig_hmac(
                    out,
                    op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                    op.cleartext.GetPtr(),
                    parts_start.data(),
                    parts_end.data(),
                    parts.size(),
                    *digest), 1);
        ret = component::Key(out, outsize);
    }

end:
    return ret;
}

std::optional<component::Key> Zig::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const auto expectedSize = repository::DigestSize(op.digestType.Get());
    if ( expectedSize == std::nullopt ) {
        return std::nullopt;
    }
    const size_t maxOutputSize = 255 * *expectedSize;
    if ( op.keySize > maxOutputSize ) {
        return std::nullopt;
    }

    uint8_t* out = nullptr;
    std::optional<uint32_t> digest = std::nullopt;
    CF_CHECK_NE(digest = Zig_detail::ToDigestId(op.digestType.Get()), std::nullopt);
    out = util::malloc(op.keySize);

    CF_CHECK_NE(cryptofuzz_zig_hkdf(
            out, op.keySize,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            op.info.GetPtr(), op.info.GetSize(),
            *digest), -1);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> Zig::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = nullptr;
    std::optional<uint32_t> digest = std::nullopt;
    CF_CHECK_NE(digest = Zig_detail::ToDigestId(op.digestType.Get()), std::nullopt);

    out = util::malloc(op.keySize);

    CF_CHECK_EQ(cryptofuzz_zig_pbkdf2(
            out, op.keySize,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            op.iterations,
            *digest), 0);

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

std::optional<component::Key> Zig::OpKDF_ARGON2(operation::KDF_ARGON2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(op.threads, 1);
    CF_CHECK_EQ(cryptofuzz_zig_argon2(
            out, op.keySize,
            op.password.GetPtr(), op.password.GetSize(),
            op.salt.GetPtr(), op.salt.GetSize(),
            op.iterations, op.memory, op.threads, op.type), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    return ret;
}

std::optional<bool> Zig::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    size_t size = 0;
    uint32_t curve = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        if ( !op.digestType.Is(CF_DIGEST("SHA256")) ) {
            return std::nullopt;
        }
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        if ( !op.digestType.Is(CF_DIGEST("SHA256")) ) {
            return std::nullopt;
        }
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        if ( !op.digestType.Is(CF_DIGEST("SHA384")) ) {
            return std::nullopt;
        }
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    std::vector<uint8_t> pub;
    std::optional<std::vector<uint8_t>> sig;

    {
        std::optional<std::vector<uint8_t>> pub_x, pub_y;

        CF_CHECK_NE(pub_x = util::DecToBin(op.signature.pub.first.ToTrimmedString(), size), std::nullopt);
        CF_CHECK_NE(pub_y = util::DecToBin(op.signature.pub.second.ToTrimmedString(), size), std::nullopt);
        pub.push_back(0x04);
        pub.insert(std::end(pub), std::begin(*pub_x), std::end(*pub_x));
        pub.insert(std::end(pub), std::begin(*pub_y), std::end(*pub_y));
    }

    CF_CHECK_NE(sig = util::ToDER(
                op.signature.signature.first.ToTrimmedString(),
                op.signature.signature.second.ToTrimmedString()), std::nullopt);

    ret = cryptofuzz_zig_ecdsa_verify(
                curve,
                pub.data(), pub.size(),
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                sig->data(), sig->size()) == 0;

end:
    return ret;
}

std::optional<bool> Zig::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    size_t size = 0;
    uint32_t curve = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> ax, ay;

    CF_CHECK_NE(ax = util::DecToBin(op.pub.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(ay = util::DecToBin(op.pub.second.ToTrimmedString(), size), std::nullopt);

    ret = cryptofuzz_zig_ecc_validatepubkey(
                curve,
                ax->data(),
                ay->data()) == 0;

end:
    return ret;
}

std::optional<component::ECC_PublicKey> Zig::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    size_t size = 0;
    uint32_t curve = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    uint8_t* r = nullptr;
    std::optional<std::vector<uint8_t>> priv;

    CF_CHECK_NE(priv = util::DecToBin(op.priv.ToTrimmedString(), size), std::nullopt);

    r = util::malloc(size * 2 + 1);

    CF_CHECK_EQ(cryptofuzz_zig_ecc_privatetopublic(
                curve,
                r,
                priv->data()), 0);

    ret = Zig_detail::To_Component_ECC_Point(r, size);

end:
    util::free(r);
    return ret;
}

std::optional<component::ECC_Point> Zig::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    size_t size = 0;
    uint32_t curve = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    uint8_t* r = nullptr;
    std::optional<std::vector<uint8_t>> ax, ay, bx, by;

    CF_CHECK_NE(ax = util::DecToBin(op.a.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(ay = util::DecToBin(op.a.second.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(bx = util::DecToBin(op.b.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(by = util::DecToBin(op.b.second.ToTrimmedString(), size), std::nullopt);

    r = util::malloc(size * 2 + 1);

    CF_CHECK_EQ(cryptofuzz_zig_ecc_point_add(
                curve,
                r,
                ax->data(),
                ay->data(),
                bx->data(),
                by->data()), 0);

    ret = Zig_detail::To_Component_ECC_Point(r, size);

end:
    util::free(r);
    return ret;
}

std::optional<component::ECC_Point> Zig::OpECC_Point_Sub(operation::ECC_Point_Sub& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    size_t size = 0;
    uint32_t curve = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    uint8_t* r = nullptr;
    std::optional<std::vector<uint8_t>> ax, ay, bx, by;

    CF_CHECK_NE(ax = util::DecToBin(op.a.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(ay = util::DecToBin(op.a.second.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(bx = util::DecToBin(op.b.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(by = util::DecToBin(op.b.second.ToTrimmedString(), size), std::nullopt);

    r = util::malloc(size * 2 + 1);

    CF_CHECK_EQ(cryptofuzz_zig_ecc_point_sub(
                curve,
                r,
                ax->data(),
                ay->data(),
                bx->data(),
                by->data()), 0);

    ret = Zig_detail::To_Component_ECC_Point(r, size);

end:
    util::free(r);
    return ret;
}

std::optional<component::ECC_Point> Zig::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    size_t size = 0;
    uint32_t curve = 0;
    int32_t alt = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    uint8_t* r = nullptr;
    std::optional<std::vector<uint8_t>> ax, ay, b;

    CF_CHECK_NE(ax = util::DecToBin(op.a.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(ay = util::DecToBin(op.a.second.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(b = util::DecToBin(op.b.ToTrimmedString(), size), std::nullopt);

    r = util::malloc(size * 2 + 1);

    try {
        alt = ds.Get<bool>() ? 1 : 0;
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    CF_CHECK_EQ(cryptofuzz_zig_ecc_point_mul(
                curve,
                r,
                ax->data(),
                ay->data(),
                b->data(),
                alt), 0);

    ret = Zig_detail::To_Component_ECC_Point(r, size);

end:
    util::free(r);
    return ret;
}

std::optional<component::ECC_Point> Zig::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    size_t size = 0;
    uint32_t curve = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    uint8_t* r = nullptr;
    std::optional<std::vector<uint8_t>> ax, ay;

    CF_CHECK_NE(ax = util::DecToBin(op.a.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(ay = util::DecToBin(op.a.second.ToTrimmedString(), size), std::nullopt);

    r = util::malloc(size * 2 + 1);

    CF_CHECK_EQ(cryptofuzz_zig_ecc_point_neg(
                curve,
                r,
                ax->data(),
                ay->data()), 0);

    ret = Zig_detail::To_Component_ECC_Point(r, size);

end:
    util::free(r);
    return ret;
}

std::optional<component::ECC_Point> Zig::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    size_t size = 0;
    uint32_t curve = 0;
    if ( op.curveType.Is(CF_ECC_CURVE("secp256r1")) ) {
        size = 32;
        curve = 0;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        size = 32;
        curve = 1;
    } else if ( op.curveType.Is(CF_ECC_CURVE("secp384r1")) ) {
        size = 48;
        curve = 2;
    } else {
        return std::nullopt;
    }

    uint8_t* r = nullptr;
    std::optional<std::vector<uint8_t>> ax, ay;

    CF_CHECK_NE(ax = util::DecToBin(op.a.first.ToTrimmedString(), size), std::nullopt);
    CF_CHECK_NE(ay = util::DecToBin(op.a.second.ToTrimmedString(), size), std::nullopt);

    r = util::malloc(size * 2 + 1);

    CF_CHECK_EQ(cryptofuzz_zig_ecc_point_dbl(
                curve,
                r,
                ax->data(),
                ay->data()), 0);

    ret = Zig_detail::To_Component_ECC_Point(r, size);

end:
    util::free(r);
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
