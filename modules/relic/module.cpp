#include "module.h"
#include "bn_ops.h"
#include <cryptofuzz/util.h>

extern "C" {
    #include <relic_conf.h>
    #include <relic.h>
}

namespace cryptofuzz {
namespace module {
namespace relic_detail {
    Datasource* global_ds = nullptr;

    void relic_fuzzer_rng(uint8_t* out, size_t size, void*) {
        CF_ASSERT(global_ds != nullptr, "Global datasource is NULL");

        if ( size == 0 ) {
            return;
        }

        try {
            const auto data = global_ds->GetData(0, size, size);
            CF_ASSERT(data.size() == (size_t)size, "Unexpected data size");
            memcpy(out, data.data(), size);

            return;
        } catch ( ... ) { }

        memset(out, 0xAA, size);
    }
}
}
}

namespace cryptofuzz {
namespace module {

relic::relic(void) :
    Module("relic") {

    CF_ASSERT(core_init() == RLC_OK, "Cannot initialize relic");
    /* noret */ rand_seed(relic_detail::relic_fuzzer_rng, nullptr);
}

namespace relic_detail {
    static bool SetCurve(const component::CurveType curveType) {

        /* TODO enable disabled curves in the relic build */

        switch ( curveType.Get() ) {
#if 0
            case    CF_ECC_CURVE("secp192r1"):
                /* noret */ ep_param_set(NIST_P192);
                return true;
#endif
#if 0
            case    CF_ECC_CURVE("secp224r1"):
                /* noret */ ep_param_set(NIST_P224);
                return true;
#endif
            case    CF_ECC_CURVE("secp256r1"):
                /* noret */ ep_param_set(NIST_P256);
                return true;
#if 0
            case    CF_ECC_CURVE("secp384r1"):
                /* noret */ ep_param_set(NIST_P384);
                return true;
#endif
#if 0
            case    CF_ECC_CURVE("secp521r1"):
                /* noret */ ep_param_set(NIST_P521);
                return true;
#endif
#if 0
            case    CF_ECC_CURVE("secp160k1"):
                /* noret */ ep_param_set(SECG_K160);
                return true;
#endif
#if 0
            case    CF_ECC_CURVE("secp192k1"):
                /* noret */ ep_param_set(SECG_K192);
                return true;
#endif
            case    CF_ECC_CURVE("secp256k1"):
                /* noret */ ep_param_set(SECG_K256);
                return true;
            default:
                return false;
        }
    }
}

std::optional<component::Digest> relic::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    switch ( op.digestType.Get() ) {
        case    CF_DIGEST("SHA224"):
            {
                uint8_t out[28];
                CF_NORET(md_map_sh224(out, op.cleartext.GetPtr(), op.cleartext.GetSize()));
                ret = component::Digest(out, 28);
            }
            break;
        case    CF_DIGEST("SHA256"):
            {
                uint8_t out[32];
                CF_NORET(md_map_sh256(out, op.cleartext.GetPtr(), op.cleartext.GetSize()));
                ret = component::Digest(out, 32);
            }
            break;
        case    CF_DIGEST("SHA384"):
            {
                uint8_t out[48];
                CF_NORET(md_map_sh384(out, op.cleartext.GetPtr(), op.cleartext.GetSize()));
                ret = component::Digest(out, 48);
            }
            break;
        case    CF_DIGEST("SHA512"):
            {
                uint8_t out[64];
                CF_NORET(md_map_sh512(out, op.cleartext.GetPtr(), op.cleartext.GetSize()));
                ret = component::Digest(out, 64);
            }
            break;
        case    CF_DIGEST("BLAKE2S160"):
            {
                uint8_t out[20];
                CF_NORET(md_map_b2s160(out, op.cleartext.GetPtr(), op.cleartext.GetSize()));
                ret = component::Digest(out, 20);
            }
            break;
        case    CF_DIGEST("BLAKE2S256"):
            {
                uint8_t out[32];
                CF_NORET(md_map_b2s256(out, op.cleartext.GetPtr(), op.cleartext.GetSize()));
                ret = component::Digest(out, 32);
            }
            break;
    }

    return ret;
}

std::optional<component::MAC> relic::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
#if MD_MAP == SH256
    if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        uint8_t mac[RLC_MD_LEN];
        CF_NORET(md_hmac(mac, op.cleartext.GetPtr(), op.cleartext.GetSize(), op.cipher.key.GetPtr(), op.cipher.key.GetSize()));
        ret = component::MAC(mac, sizeof(mac));
    }
#else
    (void)op;
#endif
    return ret;
}

std::optional<component::Ciphertext> relic::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;

    uint8_t* out = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
        case CF_CIPHER("AES_192_CBC"):
        case CF_CIPHER("AES_256_CBC"):
            {
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
                size_t outSize = static_cast<int>(op.ciphertextSize);
                out = util::malloc(op.ciphertextSize);
                CF_CHECK_EQ(
                        bc_aes_cbc_enc(
                            out, &outSize,
                            (uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(),
                            (uint8_t*)op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                            (uint8_t*)op.cipher.iv.GetPtr()), RLC_OK);
                ret = component::Ciphertext(Buffer(out, outSize));
            }
            break;
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::Cleartext> relic::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;

    uint8_t* out = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
        case CF_CIPHER("AES_192_CBC"):
        case CF_CIPHER("AES_256_CBC"):
            {
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
                size_t outSize = static_cast<int>(op.cleartextSize);
                out = util::malloc(op.cleartextSize);
                CF_CHECK_EQ(
                        bc_aes_cbc_dec(
                            out, &outSize,
                            (uint8_t*)op.ciphertext.GetPtr(), op.ciphertext.GetSize(),
                            (uint8_t*)op.cipher.key.GetPtr(), op.cipher.key.GetSize(),
                            (uint8_t*)op.cipher.iv.GetPtr()), RLC_OK);
                ret = component::Cleartext(Buffer(out, outSize));
            }
            break;
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> relic::OpKDF_X963(operation::KDF_X963& op) {
    std::optional<component::Key> ret = std::nullopt;
#if MD_MAP == SH256
    uint8_t* key = nullptr;

    if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
        if ( op.info.GetSize() == 0 ) {
            key = util::malloc(op.keySize);
            CF_NORET(md_kdf(key, op.keySize, op.secret.GetPtr(), op.secret.GetSize()));
            ret = component::Key(key, op.keySize);
        }
    }

    util::free(key);
#else
    (void)op;
#endif
    return ret;
}

std::optional<component::ECC_PublicKey> relic::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    ec_t pub;
    bool pub_initialized = false;
    relic_bignum::Bignum priv(ds), order(ds);

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set private key */
    CF_CHECK_TRUE(priv.Set(op.priv.ToString()));

    /* Check if private key is valid */
    {
        /* Must not be zero */
        CF_CHECK_EQ(bn_is_zero(priv.Get()), 0);

        /* Must be less than curve order */
        /* noret */ ec_curve_get_ord(order.Get());
        CF_CHECK_EQ(bn_cmp(priv.Get(), order.Get()), RLC_LT);
    }

    /* Compute pubkey */
    /* noret */ ec_new(pub);
    pub_initialized = true;

    RLC_TRY {
        /* noret */ ec_mul_gen(pub, priv.Get());
    } RLC_CATCH_ANY {
        goto end;
    }
    CF_CHECK_NE(ec_is_infty(pub), 1);

    {
        const int size = ec_size_bin(pub, 0);
        CF_ASSERT(size > 1, "Pubkey has invalid size");
        CF_ASSERT((size % 2) == 1, "Pubkey has invalid size");
        uint8_t* out = util::malloc(size);
        ec_write_bin(out, size, pub, 0);

        CF_ASSERT(out[0] == 0x04, "pubkey not DER encoded");

        const auto halfSize = (size-1) / 2;
        const auto X = util::BinToDec(out + 1, halfSize);
        const auto Y = util::BinToDec(out + 1 + halfSize, halfSize);

        util::free(out);

        ret = {X, Y};
    }

end:
    if ( pub_initialized ) {
        ec_free(pub);
    }
    return ret;
}

std::optional<bool> relic::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( !op.digestType.Is({CF_DIGEST("NULL"), CF_DIGEST("SHA256")}) ) {
        return ret;
    }

    ec_t pub;
    bool pub_initialized = false;
    relic_bignum::Bignum r(ds), s(ds);
    std::vector<uint8_t> pub_bytes;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set signature */
    CF_CHECK_TRUE(r.Set(op.signature.signature.first.ToString()));
    CF_CHECK_TRUE(s.Set(op.signature.signature.second.ToString()));

    /* Set pubkey */
    {
        /* noret */ ec_new(pub);
        pub_initialized = true;
        const int size = 65;
        const auto halfSize = (size-1) / 2;

        std::optional<std::vector<uint8_t>> pub_x, pub_y;
        CF_CHECK_NE(pub_x = util::DecToBin(op.signature.pub.first.ToTrimmedString(), halfSize), std::nullopt);
        CF_CHECK_NE(pub_y = util::DecToBin(op.signature.pub.second.ToTrimmedString(), halfSize), std::nullopt);

        pub_bytes.push_back(0x04);
        pub_bytes.insert(std::end(pub_bytes), std::begin(*pub_x), std::end(*pub_x));
        pub_bytes.insert(std::end(pub_bytes), std::begin(*pub_y), std::end(*pub_y));

        /* noret */ ec_read_bin(pub, pub_bytes.data(), size);
    }

    {
        Buffer CT = op.cleartext;

        if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
            CT = CT.SHA256();
        }

        CT = CT.ECDSA_RandomPad(ds, op.curveType);

        auto CTref = CT.GetVectorPtr();

        ret = cp_ecdsa_ver(r.Get(), s.Get(), CTref.data(), CTref.size(), 1, pub) == 1;
    }

end:
    if ( pub_initialized ) {
        ec_free(pub);
    }
    return ret;
}

std::optional<bool> relic::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;

    ec_t pub;
    bool pub_initialized = false;
    std::vector<uint8_t> pub_bytes;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set pubkey */
    {
        /* noret */ ec_new(pub);
        pub_initialized = true;
        const int size = 65;
        const auto halfSize = (size-1) / 2;

        std::optional<std::vector<uint8_t>> pub_x, pub_y;
        CF_CHECK_NE(pub_x = util::DecToBin(op.pub.first.ToTrimmedString(), halfSize), std::nullopt);
        CF_CHECK_NE(pub_y = util::DecToBin(op.pub.second.ToTrimmedString(), halfSize), std::nullopt);

        pub_bytes.push_back(0x04);
        pub_bytes.insert(std::end(pub_bytes), std::begin(*pub_x), std::end(*pub_x));
        pub_bytes.insert(std::end(pub_bytes), std::begin(*pub_y), std::end(*pub_y));

        /* noret */ ec_read_bin(pub, pub_bytes.data(), size);
    }

    ret = ec_on_curve(pub);

end:
    if ( pub_initialized ) {
        ec_free(pub);
    }
    return ret;
}

std::optional<component::ECDSA_Signature> relic::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.UseRandomNonce() == false ) {
        return ret;
    }
    if ( !op.digestType.Is({CF_DIGEST("NULL"), CF_DIGEST("SHA256")}) ) {
        return ret;
    }

    relic_detail::global_ds = &ds;

    ec_t pub;
    bool pub_initialized = false;
    relic_bignum::Bignum priv(ds), r(ds), s(ds);
    std::optional<std::string> R, S;
    std::string X, Y;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set privkey */
    CF_CHECK_TRUE(priv.Set(op.priv.ToString()));
    CF_CHECK_EQ(bn_is_zero(priv.Get()), 0);



    {
        Buffer CT = op.cleartext;

        if ( op.digestType.Is(CF_DIGEST("SHA256")) ) {
            CT = CT.SHA256();
        }

        CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);

        auto CTref = CT.GetVectorPtr();

        CF_CHECK_EQ(cp_ecdsa_sig(r.Get(), s.Get(), CTref.data(), CTref.size(), 1, priv.Get()), 0);
    }

    CF_CHECK_NE(R = r.ToString(), std::nullopt);
    CF_CHECK_NE(S = s.ToString(), std::nullopt);

    /* Compute pubkey */
    /* noret */ ec_new(pub);
    pub_initialized = true;
    RLC_TRY {
        /* noret */ ec_mul_gen(pub, priv.Get());
    } RLC_CATCH_ANY {
        goto end;
    }
    CF_CHECK_NE(ec_is_infty(pub), 1);

    {
        auto ct = op.cleartext.Get();

        CF_ASSERT(cp_ecdsa_ver(r.Get(), s.Get(), ct.data(), ct.size(), 1, pub) == 1, "Cannot verify generated signature");
    }

    {
        const int size = ec_size_bin(pub, 0);
        CF_ASSERT(size > 1, "Pubkey has invalid size");
        CF_ASSERT((size % 2) == 1, "Pubkey has invalid size");
        uint8_t* out = util::malloc(size);
        ec_write_bin(out, size, pub, 0);

        CF_ASSERT(out[0] == 0x04, "pubkey not DER encoded");

        const auto halfSize = (size-1) / 2;
        X = util::BinToDec(out + 1, halfSize);
        Y = util::BinToDec(out + 1 + halfSize, halfSize);

        util::free(out);
    }

    ret = { {*R, *S}, {X, Y} };

end:
    if ( pub_initialized ) {
        ec_free(pub);
    }
    relic_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> relic::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    ec_t a, b, res;
    bool a_initialized = false, b_initialized = false, res_initialized = false;
    std::vector<uint8_t> a_bytes, b_bytes;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set A */
    {
        /* noret */ ec_new(a);
        a_initialized = true;

        std::optional<std::vector<uint8_t>> x, y;
        CF_CHECK_NE(x = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
        CF_CHECK_NE(y = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);

        a_bytes.push_back(0x04);
        a_bytes.insert(std::end(a_bytes), std::begin(*x), std::end(*x));
        a_bytes.insert(std::end(a_bytes), std::begin(*y), std::end(*y));

        /* noret */ ec_read_bin(a, a_bytes.data(), 65);

        CF_CHECK_NE(ec_on_curve(a), 0)
    }

    /* Set B */
    {
        /* noret */ ec_new(b);
        b_initialized = true;

        std::optional<std::vector<uint8_t>> x, y;
        CF_CHECK_NE(x = util::DecToBin(op.b.first.ToTrimmedString(), 32), std::nullopt);
        CF_CHECK_NE(y = util::DecToBin(op.b.second.ToTrimmedString(), 32), std::nullopt);

        b_bytes.push_back(0x04);
        b_bytes.insert(std::end(b_bytes), std::begin(*x), std::end(*x));
        b_bytes.insert(std::end(b_bytes), std::begin(*y), std::end(*y));

        /* noret */ ec_read_bin(b, b_bytes.data(), 65);

        CF_CHECK_NE(ec_on_curve(b), 0)
    }

    /* Add */
    /* noret */ ec_new(res);
    res_initialized = true;
    ec_add(res, a, b);

    {
        uint8_t* out = util::malloc(65);
        ec_write_bin(out, 65, res, 0);

        const auto X = util::BinToDec(out + 1, 32);
        const auto Y = util::BinToDec(out + 1 + 32, 32);

        util::free(out);

        ret = {X, Y};
    }

end:
    if ( a_initialized ) {
        ec_free(a);
    }
    if ( b_initialized ) {
        ec_free(b);
    }
    if ( res_initialized ) {
        ec_free(res);
    }

    return ret;
}

std::optional<component::ECC_Point> relic::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    relic_bignum::Bignum b(ds);
    ec_t a, res;
    bool a_initialized = false, res_initialized = false;
    std::vector<uint8_t> a_bytes;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set A */
    {
        /* noret */ ec_new(a);
        a_initialized = true;

        std::optional<std::vector<uint8_t>> x, y;
        CF_CHECK_NE(x = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
        CF_CHECK_NE(y = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);

        a_bytes.push_back(0x04);
        a_bytes.insert(std::end(a_bytes), std::begin(*x), std::end(*x));
        a_bytes.insert(std::end(a_bytes), std::begin(*y), std::end(*y));

        /* noret */ ec_read_bin(a, a_bytes.data(), 65);

        CF_CHECK_NE(ec_on_curve(a), 0)
    }

    /* Set B */
    CF_CHECK_TRUE(b.Set(op.b.ToString()));

    /* Multiply */
    /* noret */ ec_new(res);
    res_initialized = true;
    ec_mul(res, a, b.Get());

    {
        uint8_t* out = util::malloc(65);
        ec_write_bin(out, 65, res, 0);

        const auto X = util::BinToDec(out + 1, 32);
        const auto Y = util::BinToDec(out + 1 + 32, 32);

        util::free(out);

        ret = {X, Y};
    }

end:
    if ( a_initialized ) {
        ec_free(a);
    }
    if ( res_initialized ) {
        ec_free(res);
    }

    return ret;
}

std::optional<component::ECC_Point> relic::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    ec_t a, res;
    bool a_initialized = false, res_initialized = false;
    std::vector<uint8_t> a_bytes;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set A */
    {
        /* noret */ ec_new(a);
        a_initialized = true;

        std::optional<std::vector<uint8_t>> x, y;
        CF_CHECK_NE(x = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
        CF_CHECK_NE(y = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);

        a_bytes.push_back(0x04);
        a_bytes.insert(std::end(a_bytes), std::begin(*x), std::end(*x));
        a_bytes.insert(std::end(a_bytes), std::begin(*y), std::end(*y));

        /* noret */ ec_read_bin(a, a_bytes.data(), 65);

        CF_CHECK_NE(ec_on_curve(a), 0)
    }

    /* Double */
    /* noret */ ec_new(res);
    res_initialized = true;
    ec_dbl(res, a);

    {
        uint8_t* out = util::malloc(65);
        ec_write_bin(out, 65, res, 0);

        const auto X = util::BinToDec(out + 1, 32);
        const auto Y = util::BinToDec(out + 1 + 32, 32);

        util::free(out);

        ret = {X, Y};
    }

end:
    if ( a_initialized ) {
        ec_free(a);
    }
    if ( res_initialized ) {
        ec_free(res);
    }

    return ret;
}

std::optional<component::ECC_Point> relic::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    ec_t a, res;
    bool a_initialized = false, res_initialized = false;
    std::vector<uint8_t> a_bytes;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set A */
    {
        /* noret */ ec_new(a);
        a_initialized = true;

        std::optional<std::vector<uint8_t>> x, y;
        CF_CHECK_NE(x = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
        CF_CHECK_NE(y = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);

        a_bytes.push_back(0x04);
        a_bytes.insert(std::end(a_bytes), std::begin(*x), std::end(*x));
        a_bytes.insert(std::end(a_bytes), std::begin(*y), std::end(*y));

        /* noret */ ec_read_bin(a, a_bytes.data(), 65);

        CF_CHECK_NE(ec_on_curve(a), 0)
    }

    /* Negate */
    /* noret */ ec_new(res);
    res_initialized = true;
    ec_neg(res, a);

    {
        uint8_t* out = util::malloc(65);
        ec_write_bin(out, 65, res, 0);

        const auto X = util::BinToDec(out + 1, 32);
        const auto Y = util::BinToDec(out + 1 + 32, 32);

        util::free(out);

        ret = {X, Y};
    }

end:
    if ( a_initialized ) {
        ec_free(a);
    }
    if ( res_initialized ) {
        ec_free(res);
    }

    return ret;
}

std::optional<component::Bignum> relic::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    relic_bignum::Bignum res(ds);
    std::vector<relic_bignum::Bignum> bn = {
        std::move(relic_bignum::Bignum(ds)),
        std::move(relic_bignum::Bignum(ds)),
        std::move(relic_bignum::Bignum(ds)),
        std::move(relic_bignum::Bignum(ds)),
    };

    std::unique_ptr<relic_bignum::Operation> opRunner = nullptr;

    CF_CHECK_TRUE(res.Set("0"));
    CF_CHECK_TRUE(bn[0].Set(op.bn0.ToString(ds)));
    CF_CHECK_TRUE(bn[1].Set(op.bn1.ToString(ds)));
    CF_CHECK_TRUE(bn[2].Set(op.bn2.ToString(ds)));
    CF_CHECK_TRUE(bn[3].Set(op.bn3.ToString(ds)));

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<relic_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<relic_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<relic_bignum::Mul>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<relic_bignum::Sqr>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<relic_bignum::Div>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<relic_bignum::GCD>();
            break;
        case    CF_CALCOP("ExtGCD_X(A,B)"):
            opRunner = std::make_unique<relic_bignum::ExtGCD_X>();
            break;
        case    CF_CALCOP("ExtGCD_Y(A,B)"):
            opRunner = std::make_unique<relic_bignum::ExtGCD_Y>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<relic_bignum::LCM>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<relic_bignum::InvMod>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<relic_bignum::LShift1>();
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<relic_bignum::Jacobi>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<relic_bignum::Cmp>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<relic_bignum::Mod>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<relic_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<relic_bignum::IsOdd>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<relic_bignum::IsZero>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<relic_bignum::Neg>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<relic_bignum::Sqrt>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<relic_bignum::Abs>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<relic_bignum::ExpMod>();
            break;
        case    CF_CALCOP("NumBits(A)"):
            opRunner = std::make_unique<relic_bignum::NumBits>();
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<relic_bignum::CmpAbs>();
            break;
        case    CF_CALCOP("RShift(A,B)"):
            opRunner = std::make_unique<relic_bignum::RShift>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<relic_bignum::Bit>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<relic_bignum::SetBit>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<relic_bignum::ClearBit>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);

    ret = res.ToComponentBignum();

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
