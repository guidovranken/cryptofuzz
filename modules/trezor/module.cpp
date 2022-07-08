#include "module.h"
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptofuzz/crypto.h>

extern "C" {
    #include <ecdsa.h>
    #include <secp256k1.h>
    #include <nist256p1.h>
    #include <ripemd160.h>
    #include <groestl.h>
    #include <sha2.h>
    #include <sha3.h>
    #include <hmac.h>
    #include <pbkdf2.h>
}

fuzzing::datasource::Datasource* global_ds = nullptr;

extern "C" uint32_t random32(void) {
    if ( global_ds == nullptr ) {
        /* Should not happen */
        return 1;
    }

    try {
        return global_ds->Get<uint32_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    return 1;
}

namespace cryptofuzz {
namespace module {

trezor_firmware::trezor_firmware(void) :
    Module("trezor-firmware") { }

namespace trezor_firmware_detail {
    static bool EncodeBignum(const std::string s, uint8_t* out) {
        std::vector<uint8_t> v;
        boost::multiprecision::cpp_int c(s);
        boost::multiprecision::export_bits(c, std::back_inserter(v), 8);
        if ( v.size() > 32 ) {
            return false;
        }
        const auto diff = 32 - v.size();

        memset(out, 0, 32);
        memcpy(out + diff, v.data(), v.size());

        return true;
    }

    static std::string toString(const boost::multiprecision::cpp_int& i) {
        std::stringstream ss;
        ss << i;

        if ( ss.str().empty() ) {
            return "0";
        } else {
            return ss.str();
        }
    }

    static std::optional<const ecdsa_curve*> toCurve(const component::CurveType& curveType) {
        static const std::map<uint64_t, const ecdsa_curve*> LUT = {
            /* NIST */
            { CF_ECC_CURVE("secp256r1"), &nist256p1 },
            { CF_ECC_CURVE("secp256k1"), &secp256k1 },
        };

        if ( LUT.find(curveType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(curveType.Get());
    }

    static std::optional<HasherType> toHasherType(const component::DigestType& digestType) {
        using fuzzing::datasource::ID;

        static const std::map<uint64_t, HasherType> LUT = {
            { CF_DIGEST("SHA256"), HASHER_SHA2 },
            { CF_DIGEST("SHA3-256"), HASHER_SHA3 },
            { CF_DIGEST("BLAKE2B256"), HASHER_BLAKE2B },
            { CF_DIGEST("KECCAK_256"), HASHER_SHA3K },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(digestType.Get());
    }

    static bool CheckValidity(const component::CurveType& curveType, const component::ECC_PrivateKey& priv) {
        bool ret = false;

        {
            const auto order = cryptofuzz::repository::ECC_CurveToOrder(curveType.Get());
            CF_CHECK_NE(order, std::nullopt);
            const auto order_cpp_int = boost::multiprecision::cpp_int(*order);
            const auto priv_cpp_int = boost::multiprecision::cpp_int(priv.ToTrimmedString());
            CF_CHECK_LT(priv_cpp_int, order_cpp_int);
            CF_CHECK_GT(priv_cpp_int, 0);
        }

        ret = true;
end:
        return ret;
    }

    std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(const component::CurveType& curveType, const component::ECC_PrivateKey& priv) {
        std::optional<component::ECC_PublicKey> ret = std::nullopt;
        std::vector<uint8_t> pubkey_bytes(65);
        uint8_t key[32];

        std::optional<const ecdsa_curve*> curve = std::nullopt;
        CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(curveType), std::nullopt);

        CF_CHECK_TRUE(CheckValidity(curveType, priv));

        CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                    priv.ToTrimmedString(),
                    key), true);

        /* noret */ ecdsa_get_public_key65(*curve, key, pubkey_bytes.data());

        {
            boost::multiprecision::cpp_int x, y;

            boost::multiprecision::import_bits(x, pubkey_bytes.begin() + 1, pubkey_bytes.begin() + 1 + 32);
            boost::multiprecision::import_bits(y, pubkey_bytes.begin() + 1 + 32, pubkey_bytes.end());

            ret = {trezor_firmware_detail::toString(x), trezor_firmware_detail::toString(y)};
        }
end:
        return ret;
    }

} /* namespace trezor_firmware_detail */

std::optional<component::Digest> trezor_firmware::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useHasher = false;
    try {
        useHasher = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    if ( useHasher == true ) {
        Hasher hasher;
        uint8_t hash[HASHER_DIGEST_LENGTH];
        std::optional<HasherType> hasherType = std::nullopt;
        util::Multipart parts;

        /* Initialize */
        {
            CF_CHECK_NE(hasherType = trezor_firmware_detail::toHasherType(op.digestType), std::nullopt);
            CF_NORET(hasher_Init(&hasher, *hasherType));
        }

        /* Process */
        {
            util::Multipart parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                CF_NORET(hasher_Update(&hasher, part.first, part.second));
            }
        }

        /* Finalize */
        {
            CF_NORET(hasher_Final(&hasher, hash));
            ret = component::Digest(hash, sizeof(hash));
        }
    } else {
        util::Multipart parts;

        if ( op.digestType.Get() == CF_DIGEST("RIPEMD160") ) {
            RIPEMD160_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ ripemd160_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ ripemd160_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[RIPEMD160_DIGEST_LENGTH];
                /* noret */ ripemd160_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("GROESTL_512") ) {
            sph_groestl_big_context ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ groestl512_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ groestl512_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[64];
                /* noret */ groestl512_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("SHA1") ) {
            SHA1_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ sha1_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ sha1_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[SHA1_DIGEST_LENGTH];
                /* noret */ sha1_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
            SHA256_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ sha256_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ sha256_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[SHA256_DIGEST_LENGTH];
                /* noret */ sha256_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("SHA512") ) {
            SHA512_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ sha512_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ sha512_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[SHA512_DIGEST_LENGTH];
                /* noret */ sha512_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("SHA3-224") ) {
            SHA3_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ sha3_224_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ sha3_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[224 / 8];
                /* noret */ sha3_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("SHA3-256") ) {
            SHA3_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ sha3_256_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ sha3_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[256 / 8];
                /* noret */ sha3_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("SHA3-384") ) {
            SHA3_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ sha3_384_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ sha3_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[384 / 8];
                /* noret */ sha3_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        } else if ( op.digestType.Get() == CF_DIGEST("SHA3-512") ) {
            SHA3_CTX ctx;

            /* Initialize */
            {
                memset(&ctx, 0, sizeof(ctx));
                parts = util::ToParts(ds, op.cleartext);
                /* noret */ sha3_512_Init(&ctx);

            }

            /* Process */
            for (const auto& part : parts) {
                /* noret */ sha3_Update(&ctx, part.first, part.second);
            }

            /* Finalize */
            {
                uint8_t out[512 / 8];
                /* noret */ sha3_Final(&ctx, out);

                ret = component::Digest(out, sizeof(out));
            }
        }
    }
end:

    return ret;
}

std::optional<component::MAC> trezor_firmware::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        HMAC_SHA256_CTX ctx;
        uint8_t out[SHA256_DIGEST_LENGTH];

        util::Multipart parts = util::ToParts(ds, op.cleartext);

        /* noret */ hmac_sha256_Init(&ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize());

        for (const auto& part : parts) {
            /* noret */ hmac_sha256_Update(&ctx, part.first, part.second);
        }

        /* noret */ hmac_sha256_Final(&ctx, out);

        ret = component::MAC(out, sizeof(out));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA512") ) {
        HMAC_SHA512_CTX ctx;
        uint8_t out[SHA512_DIGEST_LENGTH];

        util::Multipart parts = util::ToParts(ds, op.cleartext);

        /* noret */ hmac_sha512_Init(&ctx, op.cipher.key.GetPtr(), op.cipher.key.GetSize());

        for (const auto& part : parts) {
            /* noret */ hmac_sha512_Update(&ctx, part.first, part.second);
        }

        /* noret */ hmac_sha512_Final(&ctx, out);

        ret = component::MAC(out, sizeof(out));
    }

    return ret;
}

std::optional<component::Key> trezor_firmware::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;

    uint8_t* out = util::malloc(op.keySize);

    if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        /* noret */ pbkdf2_hmac_sha256(
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.iterations,
                out,
                op.keySize);
        ret = component::Key(out, op.keySize);
    } else if ( op.digestType.Get() == CF_DIGEST("SHA512") ) {
        /* noret */ pbkdf2_hmac_sha512(
                op.password.GetPtr(),
                op.password.GetSize(),
                op.salt.GetPtr(),
                op.salt.GetSize(),
                op.iterations,
                out,
                op.keySize);
        ret = component::Key(out, op.keySize);
    }

    util::free(out);

    return ret;
}

std::optional<component::ECC_PublicKey> trezor_firmware::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    global_ds = &ds;
    const auto ret = trezor_firmware_detail::OpECC_PrivateToPublic(op.curveType, op.priv);
    global_ds = nullptr;
    return ret;
}

std::optional<bool> trezor_firmware::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    uint8_t pubkey_bytes[65];
    curve_point point;
    std::optional<const ecdsa_curve*> curve = std::nullopt;

    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);
    pubkey_bytes[0] = 4;
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.pub.first.ToTrimmedString(),
                pubkey_bytes + 1), true);
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.pub.second.ToTrimmedString(),
                pubkey_bytes + 1 + 32), true);

    ret = ecdsa_read_pubkey(*curve, pubkey_bytes, &point) == 1;
end:
    return ret;
}

std::optional<component::ECDSA_Signature> trezor_firmware::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    global_ds = &ds;

    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    if ( op.UseRFC6979Nonce() == false ) {
        global_ds = nullptr;
        return ret;
    }

    std::optional<const ecdsa_curve*> curve = std::nullopt;
    std::optional<HasherType> hasherType = std::nullopt;
    uint8_t key[32];
    std::vector<uint8_t> sig_bytes(64);
    std::optional<component::ECC_PublicKey> pubkey = std::nullopt;

    CF_CHECK_NE(op.priv.ToTrimmedString(), "0");
    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);
    if ( op.digestType.Get() != CF_DIGEST("NULL") ) {
        CF_CHECK_NE(hasherType = trezor_firmware_detail::toHasherType(op.digestType), std::nullopt);
    }

    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.priv.ToTrimmedString(),
                key), true);

    if ( op.digestType.Get() != CF_DIGEST("NULL") ) {
        CF_CHECK_EQ(ecdsa_sign(*curve, *hasherType, key, op.cleartext.GetPtr(), op.cleartext.GetSize(), sig_bytes.data(), nullptr, nullptr), 0);
    } else {
        CF_CHECK_EQ(ecdsa_sign_digest(*curve, key, op.cleartext.ECDSA_Pad(32).GetPtr(), sig_bytes.data(), nullptr, nullptr), 0);
    }

    CF_CHECK_NE(pubkey = trezor_firmware_detail::OpECC_PrivateToPublic(op.curveType, op.priv), std::nullopt);

    {
        boost::multiprecision::cpp_int r, s;

        boost::multiprecision::import_bits(r, sig_bytes.begin(), sig_bytes.begin() + 32);
        boost::multiprecision::import_bits(s, sig_bytes.begin() + 32, sig_bytes.end());

        ret = component::ECDSA_Signature(
                {trezor_firmware_detail::toString(r), trezor_firmware_detail::toString(s)},
                *pubkey);
    }

end:
    global_ds = nullptr;
    return ret;
}

std::optional<bool> trezor_firmware::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    global_ds = &ds;

    std::optional<bool> ret = std::nullopt;
    uint8_t pubkey_bytes[65];
    uint8_t sig_bytes[64];
    std::optional<const ecdsa_curve*> curve = std::nullopt;
    std::optional<HasherType> hasherType = std::nullopt;

    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);
    if ( op.digestType.Get() != CF_DIGEST("NULL") ) {
        CF_CHECK_NE(hasherType = trezor_firmware_detail::toHasherType(op.digestType), std::nullopt);
    }

    pubkey_bytes[0] = 4;
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.signature.pub.first.ToTrimmedString(),
                pubkey_bytes + 1), true);
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.signature.pub.second.ToTrimmedString(),
                pubkey_bytes + 1 + 32), true);

    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.signature.signature.first.ToTrimmedString(),
                sig_bytes), true);
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.signature.signature.second.ToTrimmedString(),
                sig_bytes + 32), true);

    if ( op.digestType.Get() != CF_DIGEST("NULL") ) {
        ret = ecdsa_verify(*curve, *hasherType, pubkey_bytes, sig_bytes, op.cleartext.GetPtr(), op.cleartext.GetSize()) == 0;
    } else {
        static uint8_t nulls[32] = { 0 };
        const auto CT = op.cleartext.ECDSA_Pad(32);
        const auto _ret = ecdsa_verify_digest(*curve, pubkey_bytes, sig_bytes, CT.GetPtr()) == 0;
        CF_CHECK_NE(memcmp(nulls, CT.GetPtr(), 32), 0);
        ret = _ret;
    }

end:
    global_ds = nullptr;
    return ret;
}

std::optional<component::ECC_PublicKey> trezor_firmware::OpECDSA_Recover(operation::ECDSA_Recover& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    std::optional<const ecdsa_curve*> curve = std::nullopt;
    uint8_t pubkey_bytes[65];
    uint8_t sig_bytes[64];

    CF_CHECK_LTE(op.id, 3);
    CF_CHECK_EQ(op.cleartext.GetSize(), 32);
    CF_CHECK_TRUE(op.digestType.Is(CF_DIGEST("NULL")));
    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.signature.first.ToTrimmedString(),
                sig_bytes), true);
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.signature.second.ToTrimmedString(),
                sig_bytes + 32), true);

    CF_CHECK_EQ(ecdsa_recover_pub_from_sig(*curve, pubkey_bytes, sig_bytes, op.cleartext.GetPtr(), op.id), 0);

    {
        boost::multiprecision::cpp_int x, y;

        boost::multiprecision::import_bits(x, pubkey_bytes + 1, pubkey_bytes + 1 + 32);
        boost::multiprecision::import_bits(y, pubkey_bytes + 1 + 32, pubkey_bytes + sizeof(pubkey_bytes));

        ret = {trezor_firmware_detail::toString(x), trezor_firmware_detail::toString(y)};
    }

end:
    return ret;
}

std::optional<component::Secret> trezor_firmware::OpECDH_Derive(operation::ECDH_Derive& op) {
    std::optional<component::Secret> ret = std::nullopt;

    std::optional<const ecdsa_curve*> curve = std::nullopt;
    uint8_t pubkey_bytes[65];
    uint8_t key[32];
    uint8_t out[65];
    std::vector<uint8_t> out2;

    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);

    CF_CHECK_TRUE(trezor_firmware_detail::CheckValidity(op.curveType, op.priv));

    pubkey_bytes[0] = 4;
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.pub.first.ToTrimmedString(),
                pubkey_bytes + 1), true);
    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.pub.second.ToTrimmedString(),
                pubkey_bytes + 1 + 32), true);

    CF_CHECK_EQ(trezor_firmware_detail::EncodeBignum(
                op.priv.ToTrimmedString(),
                key), true);

    CF_CHECK_EQ(ecdh_multiply(*curve, key, pubkey_bytes, out), 0);

    {
        std::vector<uint8_t> sha256_input(33);

        sha256_input[0] = (out[64] & 0x01) | 0x02;
        memcpy(sha256_input.data() + 1, out + 1, 32);

        out2 = crypto::sha256(sha256_input);
    }

#if !defined(CRYPTOFUZZ_DISABLE_SPECIAL_ECDH)
    ret = component::Secret(Buffer(out2));
#endif

end:

    return ret;
}

std::optional<component::ECC_Point> trezor_firmware::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    std::optional<const ecdsa_curve*> curve = std::nullopt;
    uint8_t a_x_bytes[32], a_y_bytes[32], b_x_bytes[32], b_y_bytes[32], out_x_bytes[32], out_y_bytes[32];
    curve_point a, b;

    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);

    /* Read point A */
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.a.first.ToTrimmedString(), a_x_bytes));
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.a.second.ToTrimmedString(), a_y_bytes));
    CF_NORET(bn_read_be(a_x_bytes, &a.x));
    CF_NORET(bn_read_be(a_y_bytes, &a.y));

    /* Read point B */
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.b.first.ToTrimmedString(), b_x_bytes));
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.b.second.ToTrimmedString(), b_y_bytes));
    CF_NORET(bn_read_be(b_x_bytes, &b.x));
    CF_NORET(bn_read_be(b_y_bytes, &b.y));

    CF_NORET(point_add(*curve, &a, &b));

    CF_NORET(bn_write_be(&b.x, out_x_bytes));
    CF_NORET(bn_write_be(&b.y, out_y_bytes));

    ret = component::ECC_Point(
            util::BinToDec(out_x_bytes, sizeof(out_x_bytes)),
            util::BinToDec(out_y_bytes, sizeof(out_y_bytes))
    );
end:
    return ret;
}

std::optional<component::ECC_Point> trezor_firmware::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    std::optional<const ecdsa_curve*> curve = std::nullopt;
    uint8_t scalar_bytes[32], a_x_bytes[32], a_y_bytes[32], out_x_bytes[32], out_y_bytes[32];
    bignum256 scalar = {0};
    curve_point point;

    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);

    /* Read scalar */
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.b.ToTrimmedString(), scalar_bytes));
    CF_NORET(bn_read_be(scalar_bytes, &scalar));
    CF_CHECK_NE(bn_is_less(&scalar, &(*curve)->order), 0);

    /* Read point */
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.a.first.ToTrimmedString(), a_x_bytes));
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.a.second.ToTrimmedString(), a_y_bytes));
    CF_NORET(bn_read_be(a_x_bytes, &point.x));
    CF_NORET(bn_read_be(a_y_bytes, &point.y));

    CF_CHECK_EQ(point_multiply(*curve, &scalar, &point, &point), 0);

    CF_NORET(bn_write_be(&point.x, out_x_bytes));
    CF_NORET(bn_write_be(&point.y, out_y_bytes));

    ret = component::ECC_Point(
            util::BinToDec(out_x_bytes, sizeof(out_x_bytes)),
            util::BinToDec(out_y_bytes, sizeof(out_y_bytes))
    );
end:
    return ret;
}

std::optional<component::ECC_Point> trezor_firmware::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    std::optional<const ecdsa_curve*> curve = std::nullopt;
    uint8_t a_x_bytes[32], a_y_bytes[32], out_x_bytes[32], out_y_bytes[32];
    curve_point point;

    CF_CHECK_NE(curve = trezor_firmware_detail::toCurve(op.curveType), std::nullopt);

    /* Read point */
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.a.first.ToTrimmedString(), a_x_bytes));
    CF_CHECK_TRUE(trezor_firmware_detail::EncodeBignum(op.a.second.ToTrimmedString(), a_y_bytes));
    CF_NORET(bn_read_be(a_x_bytes, &point.x));
    CF_NORET(bn_read_be(a_y_bytes, &point.y));

    CF_NORET(point_double(*curve, &point));

    CF_NORET(bn_write_be(&point.x, out_x_bytes));
    CF_NORET(bn_write_be(&point.y, out_y_bytes));

    ret = component::ECC_Point(
            util::BinToDec(out_x_bytes, sizeof(out_x_bytes)),
            util::BinToDec(out_y_bytes, sizeof(out_y_bytes))
    );
end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
