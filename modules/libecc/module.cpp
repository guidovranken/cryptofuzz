#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <boost/lexical_cast.hpp>

extern "C" {
    #include <libsig.h>
}

namespace cryptofuzz {
namespace module {
namespace libecc_detail {
    Datasource* global_ds = nullptr;
    FILE* fp_dev_urandom = nullptr;
	const ec_sig_mapping *sm;

    std::map<uint64_t, const ec_str_params*> curveLUT;

    static void AddCurve(const uint64_t curveID, const std::string& curveName) {
        const ec_str_params *curve_params = ec_get_curve_params_by_name((const u8*)curveName.c_str(), curveName.size() + 1);

        CF_ASSERT(curve_params != nullptr, "Cannot initialize curve");

        curveLUT[curveID] = curve_params;
    }

    static const ec_str_params* GetCurve(const component::CurveType& curveType) {
        if ( curveLUT.find(curveType.Get()) == curveLUT.end() ) {
            return nullptr;
        }

        return curveLUT.at(curveType.Get());
    }
    std::optional<component::BignumPair> To_Component_BignumPair(const ec_pub_key& pub) {
        std::optional<component::BignumPair> ret = std::nullopt;

        uint8_t* out = nullptr;
        const size_t outSize = EC_PUB_KEY_EXPORT_SIZE(&pub);
        CF_ASSERT((outSize % 2) == 0, "Public key byte size is not even");
        CF_ASSERT((outSize % 3) == 0, "Public key byte size is not multiple of 3");
        out = util::malloc(outSize);
        CF_CHECK_EQ(ec_pub_key_export_to_buf(&pub, out, outSize), 0);
        {
            const size_t pointSize = outSize / 3;
            const auto X = util::BinToDec(out, pointSize);
            const auto Y = util::BinToDec(out + pointSize, pointSize);

            ret = {X, Y};
        }

end:
        util::free(out);

        return ret;
    }

    bool To_nn_t(const component::Bignum& bn, nn_t nn) {
        const auto data = util::DecToBin(bn.ToTrimmedString());
        if ( data == std::nullopt ) {
            return false;
        }
        if ( data->size() > NN_MAX_BYTE_LEN ) {
            return false;
        }

        CF_NORET(nn_init_from_buf(nn, data->data(), data->size()));

        return true;
    }

    component::Bignum To_Component_Bignum(const nn_src_t nn) {
        std::vector<uint8_t> data(nn->wlen * WORD_BYTES);

        if ( data.size() == 0 ) {
            data.resize(1);
        }

        CF_NORET(nn_export_to_buf(data.data(), data.size(), nn));

        return util::BinToDec(data.data(), data.size());
    }

    std::optional<uint16_t> To_uint16_t(const component::Bignum& bn) {
        const auto data = util::DecToBin(bn.ToTrimmedString(), sizeof(uint16_t));
        if ( data == std::nullopt ) {
            return std::nullopt;
        }

        return (((size_t)data->data()[0]) << 8) + data->data()[1];
    }

    const hash_mapping* To_hash_mapping(const uint64_t digestType) {
        switch ( digestType ) {
            case    CF_DIGEST("SHA224"):
                return get_hash_by_type(SHA224);
            case    CF_DIGEST("SHA256"):
                return get_hash_by_type(SHA256);
            case    CF_DIGEST("SHA384"):
                return get_hash_by_type(SHA384);
            case    CF_DIGEST("SHA512"):
                return get_hash_by_type(SHA512);
            case    CF_DIGEST("SHA512-224"):
                return get_hash_by_type(SHA512_224);
            case    CF_DIGEST("SHA512-256"):
                return get_hash_by_type(SHA512_256);
            case    CF_DIGEST("SHA3-224"):
                return get_hash_by_type(SHA3_224);
            case    CF_DIGEST("SHA3-256"):
                return get_hash_by_type(SHA3_256);
            case    CF_DIGEST("SHA3-384"):
                return get_hash_by_type(SHA3_384);
            case    CF_DIGEST("SHA3-512"):
                return get_hash_by_type(SHA3_512);
            default:
                return nullptr;
        }
    }
}
}
}

extern "C" int get_random(unsigned char *buf, u16 len) {
    CF_ASSERT(cryptofuzz::module::libecc_detail::global_ds != nullptr, "Global datasource is NULL");

    if ( len == 0 ) {
        return 0;
    }

    try {
        const auto data = cryptofuzz::module::libecc_detail::global_ds->GetData(0, len, len);
        memcpy(buf, data.data(), len);
        return 0;
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    CF_ASSERT(fread(buf, len, 1, cryptofuzz::module::libecc_detail::fp_dev_urandom) == 1, "Reading from /dev/urandom failed");

    return 0;
}

namespace cryptofuzz {
namespace module {

libecc::libecc(void) :
    Module("libecc") {
    CF_ASSERT((libecc_detail::fp_dev_urandom = fopen("/dev/urandom", "rb")) != NULL, "Failed to open /dev/urandom");
    CF_ASSERT((libecc_detail::sm = get_sig_by_name("ECDSA")) != nullptr, "Cannot initialize ECDSA");

    /* Load curves */
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool224r1"), "BRAINPOOLP224R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool256r1"), "BRAINPOOLP256R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool384r1"), "BRAINPOOLP384R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool512r1"), "BRAINPOOLP512R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp192r1"), "SECP192R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp224r1"), "SECP224R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp256r1"), "SECP256R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp384r1"), "SECP384R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp521r1"), "SECP521R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("frp256v1"), "FRP256V1");

    /* TODO */
#if 0
    "GOST256"
    "GOST512"
#endif
}

std::optional<component::Digest> libecc::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    hash_context ctx;
    uint8_t* out = nullptr;
    const hash_mapping* hash;

    CF_CHECK_NE(hash = libecc_detail::To_hash_mapping(op.digestType.Get()), nullptr);

    /* Initialize */
    CF_NORET(hash->hfunc_init(&ctx));

    {
    /* Process */
        const auto parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : parts) {
            if ( part.first == nullptr ) {
                continue;
            }
            CF_NORET(hash->hfunc_update(&ctx, part.first, part.second));
        }
    }

    /* Finalize */
    {
        out = util::malloc(hash->digest_size);
        CF_NORET(hash->hfunc_finalize(&ctx, out));
        ret = component::Digest(out, hash->digest_size);
    }

end:
    util::free(out);

    return ret;
}

namespace libecc_detail {
std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(Datasource& ds, const component::CurveType& curveType, const component::Bignum& _priv) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    libecc_detail::global_ds = &ds;

    ec_priv_key priv;
	ec_pub_key pub;
    uint8_t* out = nullptr;
	ec_params params;
    ec_sig_alg_type sig_type;
    std::optional<std::vector<uint8_t>> priv_bytes;
    const ec_str_params* curve_params;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(curveType), nullptr);
    CF_NORET(import_params(&params, curve_params));

    sig_type = libecc_detail::sm->type;

    {
        const auto priv_str = _priv.ToTrimmedString();
        CF_CHECK_NE(priv_str, "0");
        CF_CHECK_NE(priv_str, *cryptofuzz::repository::ECC_CurveToOrder(curveType.Get()));
        CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str), std::nullopt);
        CF_CHECK_LTE(priv_bytes->size(), NN_MAX_BYTE_LEN);
        CF_NORET(ec_priv_key_import_from_buf(&priv, &params, priv_bytes->data(), priv_bytes->size(), sig_type));
        memset(&pub, 0, sizeof(pub));
        CF_CHECK_EQ(init_pubkey_from_privkey(&pub, &priv), 0);
        CF_CHECK_EQ(pub.magic, PUB_KEY_MAGIC);

        aff_pt Q_aff;
        prj_pt_to_aff(&Q_aff, &pub.y);
        ec_shortw_aff_to_prj(&pub.y, &Q_aff);
    }

    {
        const auto _ret = libecc_detail::To_Component_BignumPair(pub);
        CF_CHECK_TRUE(_priv.IsLessThan(*cryptofuzz::repository::ECC_CurveToOrder(curveType.Get())));
        ret = _ret;
    }

end:
    util::free(out);

    libecc_detail::global_ds = nullptr;
    return ret;
}
}

std::optional<component::ECC_PublicKey> libecc::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    return libecc_detail::OpECC_PrivateToPublic(ds, op.curveType, op.priv);
}

std::optional<component::ECDSA_Signature> libecc::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    if ( op.UseRandomNonce() == false && op.UseSpecifiedNonce() == false ) {
        return std::nullopt;
    }

    if ( op.digestType.Get() != CF_DIGEST("NULL") ) {
        return std::nullopt;
    }

    std::optional<component::ECDSA_Signature> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::ECC_PublicKey> pub = std::nullopt;
    const ec_str_params* curve_params;
    std::optional<std::vector<uint8_t>> priv_bytes;
	ec_params params;
	ec_key_pair kp;
    struct ec_sign_context ctx;
    size_t signature_size = 0;
    uint8_t* signature = nullptr;
    std::optional<std::vector<uint8_t>> nonce_bytes;

    CF_CHECK_NE(pub = libecc_detail::OpECC_PrivateToPublic(ds, op.curveType, op.priv), std::nullopt);

    libecc_detail::global_ds = &ds;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_NORET(import_params(&params, curve_params));

    {
        const auto priv_str = op.priv.ToTrimmedString();
        CF_CHECK_NE(priv_str, "0");
        CF_CHECK_NE(priv_str, *cryptofuzz::repository::ECC_CurveToOrder(op.curveType.Get()));
        CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str), std::nullopt);
        CF_CHECK_LTE(priv_bytes->size(), NN_MAX_BYTE_LEN);
        CF_CHECK_EQ(ec_key_pair_import_from_priv_key_buf(&kp,
                    &params,
                    priv_bytes->data(), priv_bytes->size(),
                    ECDSA), 0);
    }

    signature_size = ECDSA_SIGLEN(kp.priv_key.params->ec_gen_order_bitlen);
    CF_ASSERT((signature_size % 2) == 0, "Signature size is not multiple of 2");
    signature = util::malloc(signature_size);

    CF_CHECK_EQ(ec_sign_init(&ctx, &kp, ECDSA, SHA256), 0);

    if ( op.UseSpecifiedNonce() == true ) {
        /* ecdsa_sign_raw crashes if nonce is 0 */
        CF_CHECK_NE(op.nonce.ToTrimmedString(), "0");

        CF_CHECK_NE(nonce_bytes = util::DecToBin(op.nonce.ToTrimmedString()), std::nullopt);
    }

    CF_INSTALL_JMP();

    CF_CHECK_EQ(ecdsa_sign_raw(
                &ctx,
                op.cleartext.GetPtr(), op.cleartext.GetSize(),
                signature, signature_size,
                op.UseSpecifiedNonce() ? nonce_bytes->data() : nullptr,
                op.UseSpecifiedNonce() ? nonce_bytes->size() : 0), 0);
    ret = {
        {
            util::BinToDec(signature, signature_size / 2),
            util::BinToDec(signature + (signature_size / 2), signature_size / 2),
        },
        *pub
    };

end:
    CF_RESTORE_JMP();

    util::free(signature);

    libecc_detail::global_ds = nullptr;
    return ret;
}

std::optional<bool> libecc::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    if ( op.digestType.Get() != CF_DIGEST("NULL") ) {
        return std::nullopt;
    }

    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    libecc_detail::global_ds = &ds;

    const ec_str_params* curve_params;
	ec_params params;
    struct ec_verify_context ctx;
	ec_key_pair kp;
    std::vector<uint8_t> pub;
    std::vector<uint8_t> sig;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_NORET(import_params(&params, curve_params));

    {
	    const size_t signature_size = ECDSA_SIGLEN(params.ec_gen_order_bitlen);
        CF_ASSERT((signature_size % 2) == 0, "Signature size is not multiple of 2");

        std::optional<std::vector<uint8_t>> R, S;
        CF_CHECK_NE(R = util::DecToBin(op.signature.signature.first.ToTrimmedString(), signature_size / 2), std::nullopt);
        CF_CHECK_NE(S = util::DecToBin(op.signature.signature.second.ToTrimmedString(), signature_size / 2), std::nullopt);

        sig.insert(std::end(sig), std::begin(*R), std::end(*R));
        sig.insert(std::end(sig), std::begin(*S), std::end(*S));
    }
    {
        const size_t pubSize = BYTECEIL(params.ec_curve.a.ctx->p_bitlen) * 3;
        CF_ASSERT((pubSize % 2) == 0, "Public key byte size is not even");
        CF_ASSERT((pubSize % 3) == 0, "Public key byte size is not multiple of 3");
        pub.resize(pubSize, 0);

        const size_t pointSize = pubSize / 3;
        std::optional<std::vector<uint8_t>> X, Y, Z;
        CF_CHECK_NE(X = util::DecToBin(op.signature.pub.first.ToTrimmedString(), pointSize), std::nullopt);
        CF_CHECK_NE(Y = util::DecToBin(op.signature.pub.second.ToTrimmedString(), pointSize), std::nullopt);
        CF_CHECK_NE(Z = util::DecToBin("1", pointSize), std::nullopt);

        memcpy(pub.data(), X->data(), pointSize);
        memcpy(pub.data() + pointSize, Y->data(), pointSize);
        memcpy(pub.data() + pointSize * 2, Z->data(), pointSize);

        CF_INSTALL_JMP();

        CF_CHECK_EQ(ec_pub_key_import_from_buf(
                    &kp.pub_key,
                    &params,
                    pub.data(), pub.size(),
                    libecc_detail::sm->type), 0);

        CF_CHECK_EQ(prj_pt_is_on_curve(&kp.pub_key.y), 1);
    }


    CF_CHECK_EQ(ec_verify_init(&ctx, &(kp.pub_key), sig.data(), sig.size(), ECDSA, SHA256), 0);
    ret = ecdsa_verify_raw(&ctx, op.cleartext.GetPtr(), op.cleartext.GetSize()) == 0;

end:
    CF_RESTORE_JMP();

    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::Bignum> libecc::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    nn result, a, b, c;

    CF_INSTALL_JMP();

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_NORET(nn_add(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Sub(A,B)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_CHECK_GT(nn_cmp(&a, &b), 0);

            CF_NORET(nn_sub(&result, &a, &b));
            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Mul(A,B)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_NORET(nn_mul(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Mod(A,B)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_CHECK_EQ(nn_iszero(&b), 0);

            CF_NORET(nn_mod(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_CHECK_EQ(nn_modinv(&result, &a, &b), 1);

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("LShift1(A)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_NORET(nn_lshift(&result, &a, 1));

            CF_CHECK_LT(nn_bitlen(&a), NN_MAX_BIT_LEN);

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("RShift(A,B)"):
            {
                std::optional<uint16_t> count;
                CF_NORET(nn_init(&result, 0));
                CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
                CF_CHECK_NE(count = libecc_detail::To_uint16_t(op.bn1), std::nullopt);

                CF_NORET(nn_rshift(&result, &a, *count));

                ret = libecc_detail::To_Component_Bignum(&result);
            }
            break;
        case    CF_CALCOP("GCD(A,B)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_NORET(nn_gcd(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Sqr(A)"):
            CF_NORET(nn_init(&result, 0));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_NORET(nn_sqr(&result, &a));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("IsZero(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            ret = std::to_string( nn_iszero(&a) );
            break;
        case    CF_CALCOP("IsOne(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            ret = std::to_string( nn_isone(&a) );
            break;
        case    CF_CALCOP("IsOdd(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            ret = std::to_string( nn_isodd(&a) );
            break;
        case    CF_CALCOP("And(A,B)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_NORET(nn_and(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Or(A,B)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_NORET(nn_or(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Xor(A,B)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_NORET(nn_xor(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("NumBits(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            ret = std::to_string( nn_bitlen(&a) );
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            CF_NORET(nn_init(&result, 0));

            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn2, &c));

            CF_CHECK_TRUE(nn_isodd(&c));
            CF_CHECK_GT(nn_cmp(&c, &a), 0);
            CF_CHECK_GT(nn_cmp(&c, &b), 0);

            CF_NORET(nn_mul_mod(&result, &a, &b, &c));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            CF_NORET(nn_init(&result, 0));

            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn2, &c));

            CF_CHECK_GT(nn_cmp(&c, &a), 0);
            CF_CHECK_GT(nn_cmp(&c, &b), 0);

            CF_NORET(nn_mod_add(&result, &a, &b, &c));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            CF_NORET(nn_init(&result, 0));

            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn2, &c));

            CF_CHECK_GT(nn_cmp(&c, &a), 0);
            CF_CHECK_GT(nn_cmp(&c, &b), 0);

            CF_NORET(nn_mod_sub(&result, &a, &b, &c));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Bit(A,B)"):
            try {
                CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
                const auto count = boost::lexical_cast<bitcnt_t>(op.bn1.ToTrimmedString());
                ret = std::to_string( nn_getbit(&a, count) );
            } catch ( const boost::bad_lexical_cast &e ) {
            }
            break;
    }

end:
    CF_RESTORE_JMP();

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
