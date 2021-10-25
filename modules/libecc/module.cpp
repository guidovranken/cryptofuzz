#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <boost/lexical_cast.hpp>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

extern "C" {
    #include <libsig.h>
}

namespace cryptofuzz {
namespace module {
namespace libecc_detail {
    Datasource* global_ds = nullptr;
    FILE* fp_dev_urandom = nullptr;
    const ec_sig_mapping *sm_ecdsa, *sm_ecgdsa, *sm_ecrdsa;

    std::map<uint64_t, const ec_str_params*> curveLUT;

    static void AddCurve(const uint64_t curveID, const std::string& curveName) {
        int ret;
        const ec_str_params *curve_params;

        ret = ec_get_curve_params_by_name((const u8*)curveName.c_str(), curveName.size() + 1, &curve_params);

        CF_ASSERT((!ret) && (curve_params != nullptr), "Cannot initialize curve");

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
        if ( (8 * data->size()) > NN_USABLE_MAX_BIT_LEN ) {
            return false;
        }

        CF_ASSERT(!nn_init_from_buf(nn, data->data(), data->size()), "nn_init_from_buf error " __FILE__ ":" TOSTRING(__LINE__));

        return true;
    }

    component::Bignum To_Component_Bignum(const nn_src_t nn) {
        std::vector<uint8_t> data(nn->wlen * WORD_BYTES);

        if ( data.size() == 0 ) {
            data.resize(1);
        }

        CF_ASSERT(!nn_export_to_buf(data.data(), data.size(), nn), "nn_export_to_buf error " __FILE__ ":" TOSTRING(__LINE__));

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
        const hash_mapping *hm;
        switch ( digestType ) {
            case    CF_DIGEST("SHA224"):
                CF_ASSERT(!get_hash_by_type(SHA224, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA256"):
                CF_ASSERT(!get_hash_by_type(SHA256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA384"):
                CF_ASSERT(!get_hash_by_type(SHA384, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA512"):
                CF_ASSERT(!get_hash_by_type(SHA512, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA512-224"):
                CF_ASSERT(!get_hash_by_type(SHA512_224, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA512-256"):
                CF_ASSERT(!get_hash_by_type(SHA512_256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-224"):
                CF_ASSERT(!get_hash_by_type(SHA3_224, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-256"):
                CF_ASSERT(!get_hash_by_type(SHA3_256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-384"):
                CF_ASSERT(!get_hash_by_type(SHA3_384, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-512"):
                CF_ASSERT(!get_hash_by_type(SHA3_512, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SM3"):
                CF_ASSERT(!get_hash_by_type(SM3, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHAKE256_114"):
                CF_ASSERT(!get_hash_by_type(SHAKE256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("STREEBOG-256"):
                CF_ASSERT(!get_hash_by_type(STREEBOG256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("STREEBOG-512"):
                CF_ASSERT(!get_hash_by_type(STREEBOG512, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            default:
                return nullptr;
        }
    }

    std::optional<hash_alg_type> To_hash_alg_type(const uint64_t digestType) {
        switch ( digestType ) {
            case    CF_DIGEST("SHA224"):
                return SHA224;
            case    CF_DIGEST("SHA256"):
                return SHA256;
            case    CF_DIGEST("SHA384"):
                return SHA384;
            case    CF_DIGEST("SHA512"):
                return SHA512;
            case    CF_DIGEST("SHA512-224"):
                return SHA512_224;
            case    CF_DIGEST("SHA512-256"):
                return SHA512_256;
            case    CF_DIGEST("SHA3-224"):
                return SHA3_224;
            case    CF_DIGEST("SHA3-256"):
                return SHA3_256;
            case    CF_DIGEST("SHA3-384"):
                return SHA3_384;
            case    CF_DIGEST("SHA3-512"):
                return SHA3_512;
            case    CF_DIGEST("SM3"):
                return SM3;
            case    CF_DIGEST("SHAKE256_114"):
                return SHAKE256;
            case    CF_DIGEST("STREEBOG-256"):
                return STREEBOG256;
            case    CF_DIGEST("STREEBOG-512"):
                return STREEBOG512;
            default:
                return std::nullopt;
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
    CF_ASSERT((!get_sig_by_name("ECDSA", &(libecc_detail::sm_ecdsa))) && ((libecc_detail::sm_ecdsa) != nullptr), "Cannot initialize ECDSA");
    CF_ASSERT((!get_sig_by_name("ECGDSA", &(libecc_detail::sm_ecgdsa))) && ((libecc_detail::sm_ecgdsa) != nullptr), "Cannot initialize ECGDSA");
    CF_ASSERT((!get_sig_by_name("ECRDSA", &(libecc_detail::sm_ecrdsa))) && ((libecc_detail::sm_ecrdsa) != nullptr), "Cannot initialize ECRDSA");

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
    libecc_detail::AddCurve(CF_ECC_CURVE("secp256k1"), "SECP256K1");

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
    CF_ASSERT(!(hash->hfunc_init(&ctx)), "hfunc_init error " __FILE__ ":" TOSTRING(__LINE__));

    {
    /* Process */
        const auto parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : parts) {
            if ( part.first == nullptr ) {
                continue;
            }
            CF_ASSERT(!(hash->hfunc_update(&ctx, part.first, part.second)), "hfunc_update error " __FILE__ ":" TOSTRING(__LINE__));
        }
    }

    /* Finalize */
    {
        out = util::malloc(hash->digest_size);
        CF_ASSERT(!(hash->hfunc_finalize(&ctx, out)), "hfunc_finalize error " __FILE__ ":" TOSTRING(__LINE__));

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
    ec_alg_type sig_type;
    std::optional<std::vector<uint8_t>> priv_bytes;
    const ec_str_params* curve_params;
    std::string priv_str;
    aff_pt Q_aff;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    sig_type = libecc_detail::sm_ecdsa->type;

    priv_str = _priv.ToTrimmedString();
    CF_CHECK_NE(priv_str, "0");
    CF_CHECK_NE(priv_str, *cryptofuzz::repository::ECC_CurveToOrder(curveType.Get()));
    CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str), std::nullopt);
    CF_CHECK_LTE((8 * priv_bytes->size()), NN_USABLE_MAX_BIT_LEN);

    CF_ASSERT(!ec_priv_key_import_from_buf(&priv, &params, priv_bytes->data(), priv_bytes->size(), sig_type), "ec_priv_key_import_from_buf error " __FILE__ ":" TOSTRING(__LINE__));
    memset(&pub, 0, sizeof(pub));
    CF_CHECK_EQ(init_pubkey_from_privkey(&pub, &priv), 0);
    CF_CHECK_EQ(pub.magic, PUB_KEY_MAGIC);

    CF_ASSERT(!prj_pt_to_aff(&Q_aff, &pub.y), "prj_pt_to_aff error " __FILE__ ":" TOSTRING(__LINE__));
    CF_ASSERT(!ec_shortw_aff_to_prj(&pub.y, &Q_aff), "ec_shortw_aff_to_prj error " __FILE__ ":" TOSTRING(__LINE__));

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


namespace libecc_detail {

    typedef int (*ecxdsa_sign_raw_t)(struct ec_sign_context *ctx, const u8 *input, u8 inputlen, u8 *sig, u8 siglen, const u8 *nonce, u8 noncelen);
    typedef int (*ecxdsa_sign_update_t)(struct ec_sign_context *ctx, const u8 *chunk, u32 chunklen);
    typedef int (*ecxdsa_sign_finalize_t)(struct ec_sign_context *ctx, u8 *sig, u8 siglen);
    typedef int (*ecxdsa_rfc6979_sign_finalize_t)(struct ec_sign_context *ctx, u8 *sig, u8 siglen, ec_alg_type key_type);

    template <class Operation, ec_alg_type AlgType>
    std::optional<component::ECDSA_Signature> ECxDSA_Sign(
            const Operation& op,
            const ecxdsa_sign_raw_t ecxdsa_sign_raw,
            const ecxdsa_sign_update_t ecxdsa_sign_update,
            const ecxdsa_sign_finalize_t ecxdsa_sign_finalize,
            const ecxdsa_rfc6979_sign_finalize_t ecxdsa_rfc6979_sign_finalize = nullptr) {
        /* ecdsa_sign_raw supports messages up to 255 bytes */
        if ( op.cleartext.GetSize() > 255 ) {
            return std::nullopt;
        }

        if ( op.UseRFC6979Nonce() && ecxdsa_rfc6979_sign_finalize == nullptr ) {
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
        std::optional<hash_alg_type> hash;
        util::Multipart parts;
        const ec_alg_type alg = op.UseRFC6979Nonce() ? DECDSA : AlgType;

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_TRUE(op.UseRandomNonce() || op.UseRFC6979Nonce());
            CF_CHECK_NE(hash = libecc_detail::To_hash_alg_type(op.digestType.Get()), std::nullopt);
        } else {
            CF_CHECK_TRUE(op.UseSpecifiedNonce());
        }

        CF_CHECK_NE(pub = libecc_detail::OpECC_PrivateToPublic(ds, op.curveType, op.priv), std::nullopt);

        libecc_detail::global_ds = &ds;

        /* Load curve */
        CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
        CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

        {
            const auto priv_str = op.priv.ToTrimmedString();
            CF_CHECK_NE(priv_str, "0");
            CF_CHECK_NE(priv_str, *cryptofuzz::repository::ECC_CurveToOrder(op.curveType.Get()));
            CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str), std::nullopt);
            CF_CHECK_LTE((8 * priv_bytes->size()), NN_USABLE_MAX_BIT_LEN);
            CF_CHECK_EQ(ec_key_pair_import_from_priv_key_buf(&kp,
                        &params,
                        priv_bytes->data(), priv_bytes->size(),
                        alg), 0);
        }

        signature_size = ECDSA_SIGLEN(kp.priv_key.params->ec_gen_order_bitlen);
        CF_ASSERT((signature_size % 2) == 0, "Signature size is not multiple of 2");
        signature = util::malloc(signature_size);

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_EQ(ec_sign_init(&ctx, &kp, alg, SHA256, nullptr, 0), 0);
        } else {
            CF_CHECK_EQ(ec_sign_init(&ctx, &kp, alg, *hash, nullptr, 0), 0);
        }

        if ( op.UseSpecifiedNonce() == true ) {
            /* ecdsa_sign_raw crashes if nonce is 0 */
            CF_CHECK_NE(op.nonce.ToTrimmedString(), "0");

            CF_CHECK_NE(nonce_bytes = util::DecToBin(op.nonce.ToTrimmedString()), std::nullopt);

            /* ecdsa_sign_raw supports nonce up to 255 bytes */
            CF_CHECK_LTE(nonce_bytes->size(), 255);
        }

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            parts = util::ToParts(ds, op.cleartext);
        }

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_EQ(ecxdsa_sign_raw(
                        &ctx,
                        op.cleartext.GetPtr(), op.cleartext.GetSize(),
                        signature, signature_size,
                        op.UseSpecifiedNonce() ? nonce_bytes->data() : nullptr,
                        op.UseSpecifiedNonce() ? nonce_bytes->size() : 0), 0);
        } else {
            for (const auto& part : parts) {
                CF_CHECK_EQ(ecxdsa_sign_update(&ctx, part.first, part.second), 0);
            }

            if ( op.UseRandomNonce() ) {
                CF_CHECK_EQ(ecxdsa_sign_finalize(&ctx, signature, signature_size), 0);
            } else if ( op.UseRFC6979Nonce() ) {
                CF_CHECK_EQ(ecxdsa_rfc6979_sign_finalize(&ctx, signature, signature_size, DECDSA), 0);
            } else {
                CF_UNREACHABLE();
            }
        }

        ret = {
            {
                util::BinToDec(signature, signature_size / 2),
                util::BinToDec(signature + (signature_size / 2), signature_size / 2),
            },
            *pub
        };

end:
        util::free(signature);

        libecc_detail::global_ds = nullptr;
        return ret;
    }

    typedef int (*ecxdsa_verify_raw_t)(struct ec_verify_context *ctx, const u8 *input, u8 inputlen);
    typedef int (*ecxdsa_verify_update_t)(struct ec_verify_context *ctx, const u8 *chunk, u32 chunklen);
    typedef int (*ecxdsa_verify_finalize_t)(struct ec_verify_context *ctx);

    template <class Operation, ec_alg_type AlgType>
    std::optional<bool> ECxDSA_Verify(
            const Operation& op,
            const ec_sig_mapping* sm,
            const ecxdsa_verify_raw_t ecxdsa_verify_raw,
            const ecxdsa_verify_update_t ecxdsa_verify_update,
            const ecxdsa_verify_finalize_t ecxdsa_verify_finalize) {
        /* ecdsa_verify_raw supports messages up to 255 bytes */
        if ( op.cleartext.GetSize() > 255 ) {
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
        std::optional<std::vector<uint8_t>> X, Y, Z;
        std::optional<hash_alg_type> hash;
        util::Multipart parts;

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_NE(hash = libecc_detail::To_hash_alg_type(op.digestType.Get()), std::nullopt);
        }

        /* Load curve */
        CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
        CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

        {
            const size_t signature_size = ECDSA_SIGLEN(params.ec_gen_order_bitlen);
            CF_ASSERT((signature_size % 2) == 0, "Signature size is not multiple of 2");

            std::optional<std::vector<uint8_t>> R, S;
            CF_CHECK_NE(R = util::DecToBin(op.signature.signature.first.ToTrimmedString(), signature_size / 2), std::nullopt);
            CF_CHECK_NE(S = util::DecToBin(op.signature.signature.second.ToTrimmedString(), signature_size / 2), std::nullopt);

            sig.insert(std::end(sig), std::begin(*R), std::end(*R));
            sig.insert(std::end(sig), std::begin(*S), std::end(*S));
        }

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            parts = util::ToParts(ds, op.cleartext);
        }

        {
            const size_t pubSize = BYTECEIL(params.ec_curve.a.ctx->p_bitlen) * 3;
            CF_ASSERT((pubSize % 2) == 0, "Public key byte size is not even");
            CF_ASSERT((pubSize % 3) == 0, "Public key byte size is not multiple of 3");
            pub.resize(pubSize, 0);

            const size_t pointSize = pubSize / 3;
            CF_CHECK_NE(X = util::DecToBin(op.signature.pub.first.ToTrimmedString(), pointSize), std::nullopt);
            CF_CHECK_NE(Y = util::DecToBin(op.signature.pub.second.ToTrimmedString(), pointSize), std::nullopt);
            CF_CHECK_NE(Z = util::DecToBin("1", pointSize), std::nullopt);

            memcpy(pub.data(), X->data(), pointSize);
            memcpy(pub.data() + pointSize, Y->data(), pointSize);
            memcpy(pub.data() + pointSize * 2, Z->data(), pointSize);

            CF_CHECK_EQ(ec_pub_key_import_from_buf(
                        &kp.pub_key,
                        &params,
                        pub.data(), pub.size(),
                        sm->type), 0);

            int check;
            CF_ASSERT(!prj_pt_is_on_curve(&kp.pub_key.y, &check), "prj_pt_is_on_curve error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_EQ(check, 1);
        }

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_EQ(ec_verify_init(&ctx, &(kp.pub_key), sig.data(), sig.size(), AlgType, SHA256, nullptr, 0), 0);
        } else {
            CF_CHECK_EQ(ec_verify_init(&ctx, &(kp.pub_key), sig.data(), sig.size(), AlgType, *hash, nullptr, 0), 0);
        }

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            const auto cleartext_ptr = op.cleartext.GetPtr();

            /* libecc has an explicit check for NULL input which causes ecdsa_verify_raw
             * to return false even if the signature is valid.
             *
             * See also OSS-Fuzz issue #33808
             */
            CF_CHECK_NE(cleartext_ptr, nullptr);

            ret = ecxdsa_verify_raw(&ctx, cleartext_ptr, op.cleartext.GetSize()) == 0;
        } else {
            for (const auto& part : parts) {
                CF_CHECK_EQ(ecxdsa_verify_update(&ctx, part.first, part.second), 0);
            }

            ret = ecxdsa_verify_finalize(&ctx) == 0;
        }

end:
        libecc_detail::global_ds = nullptr;

        return ret;
    }
} /* namespace libecc_detail */

std::optional<component::ECDSA_Signature> libecc::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    return libecc_detail::ECxDSA_Sign<operation::ECDSA_Sign, ECDSA>(op, ecdsa_sign_raw, _ecdsa_sign_update, _ecdsa_sign_finalize, __ecdsa_sign_finalize);
}

std::optional<component::ECGDSA_Signature> libecc::OpECGDSA_Sign(operation::ECGDSA_Sign& op) {
    return libecc_detail::ECxDSA_Sign<operation::ECGDSA_Sign, ECGDSA>(op, ecgdsa_sign_raw, _ecgdsa_sign_update, _ecgdsa_sign_finalize);
}

std::optional<component::ECRDSA_Signature> libecc::OpECRDSA_Sign(operation::ECRDSA_Sign& op) {
    return libecc_detail::ECxDSA_Sign<operation::ECRDSA_Sign, ECRDSA>(op, ecrdsa_sign_raw, _ecrdsa_sign_update, _ecrdsa_sign_finalize);
}

std::optional<bool> libecc::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    return libecc_detail::ECxDSA_Verify<operation::ECDSA_Verify, ECDSA>(op, libecc_detail::sm_ecdsa, ecdsa_verify_raw, _ecdsa_verify_update, _ecdsa_verify_finalize);
}

std::optional<bool> libecc::OpECGDSA_Verify(operation::ECGDSA_Verify& op) {
    return libecc_detail::ECxDSA_Verify<operation::ECGDSA_Verify, ECGDSA>(op, libecc_detail::sm_ecgdsa, ecgdsa_verify_raw, _ecgdsa_verify_update, _ecgdsa_verify_finalize);
}

std::optional<bool> libecc::OpECRDSA_Verify(operation::ECRDSA_Verify& op) {
    return libecc_detail::ECxDSA_Verify<operation::ECRDSA_Verify, ECRDSA>(op, libecc_detail::sm_ecrdsa, ecrdsa_verify_raw, _ecrdsa_verify_update, _ecrdsa_verify_finalize);
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a, b;
    aff_pt res_aff;
    fp x, y, z;

    const auto ax_bin = util::DecToBin(op.a.first.ToTrimmedString());
    const auto ay_bin = util::DecToBin(op.a.second.ToTrimmedString());
    const auto bx_bin = util::DecToBin(op.b.first.ToTrimmedString());
    const auto by_bin = util::DecToBin(op.b.second.ToTrimmedString());

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    CF_ASSERT(!prj_pt_init(&res, &(params.ec_curve)), "prj_pt_init error " __FILE__ ":" TOSTRING(__LINE__));

    {
        CF_CHECK_TRUE(!fp_init_from_buf(&x, &(params.ec_fp), ax_bin->data(), ax_bin->size()));

        CF_CHECK_TRUE(!fp_init_from_buf(&y, &(params.ec_fp), ay_bin->data(), ay_bin->size()));

        CF_ASSERT(!fp_init(&z, &(params.ec_fp)), "fp_init error " __FILE__ ":" TOSTRING(__LINE__));
        CF_ASSERT(!fp_one(&z), "fp_one error " __FILE__ ":" TOSTRING(__LINE__));

        CF_CHECK_TRUE(!prj_pt_init_from_coords(&a, &(params.ec_curve), &x, &y, &z));

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    {
        CF_CHECK_TRUE(!fp_init_from_buf(&x, &(params.ec_fp), bx_bin->data(), bx_bin->size()));

        CF_CHECK_TRUE(!fp_init_from_buf(&y, &(params.ec_fp), by_bin->data(), by_bin->size()));

        CF_ASSERT(!fp_init(&z, &(params.ec_fp)), "fp_init error " __FILE__ ":" TOSTRING(__LINE__));
        CF_ASSERT(!fp_one(&z), "fp_one error " __FILE__ ":" TOSTRING(__LINE__));

        CF_CHECK_TRUE(!prj_pt_init_from_coords(&b, &(params.ec_curve), &x, &y, &z));

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    CF_CHECK_TRUE(!prj_pt_add(&res, &a, &b));

    CF_CHECK_TRUE(!prj_pt_to_aff(&res_aff, &res));

    {
        const size_t coordinateSize = BYTECEIL(params.ec_curve.a.ctx->p_bitlen);
        const size_t pointSize = coordinateSize * 2;

        uint8_t out_bytes[pointSize];

        CF_CHECK_EQ(aff_pt_export_to_buf(&res_aff, out_bytes, pointSize), 0);

        const auto X = util::BinToDec(out_bytes, coordinateSize);
        const auto Y = util::BinToDec(out_bytes + coordinateSize, coordinateSize);

        ret = {X, Y};
    }

    prj_pt_uninit(&res);
    prj_pt_uninit(&a);
    prj_pt_uninit(&b);

end:

    return ret;
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a;
    nn b;
    aff_pt res_aff;
    fp x, y, z;

    libecc_detail::global_ds = &ds;

    const auto ax_bin = util::DecToBin(op.a.first.ToTrimmedString());
    const auto ay_bin = util::DecToBin(op.a.second.ToTrimmedString());

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    CF_ASSERT(!prj_pt_init(&res, &(params.ec_curve)), "prj_pt_init error " __FILE__ ":" TOSTRING(__LINE__));

    {
        CF_CHECK_TRUE(!fp_init_from_buf(&x, &(params.ec_fp), ax_bin->data(), ax_bin->size()));

        CF_CHECK_TRUE(!fp_init_from_buf(&y, &(params.ec_fp), ay_bin->data(), ay_bin->size()));

        CF_ASSERT(!fp_init(&z, &(params.ec_fp)), "fp_init error " __FILE__ ":" TOSTRING(__LINE__));
        CF_ASSERT(!fp_one(&z), "fp_one error " __FILE__ ":" TOSTRING(__LINE__));

        CF_CHECK_TRUE(!prj_pt_init_from_coords(&a, &(params.ec_curve), &x, &y, &z));

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    CF_CHECK_TRUE(libecc_detail::To_nn_t(op.b, &b));

    CF_CHECK_TRUE(!prj_pt_mul(&res, &b, &a));

    CF_CHECK_TRUE(!prj_pt_to_aff(&res_aff, &res));

    {
        const size_t coordinateSize = BYTECEIL(params.ec_curve.a.ctx->p_bitlen);
        const size_t pointSize = coordinateSize * 2;

        uint8_t out_bytes[pointSize];

        CF_CHECK_EQ(aff_pt_export_to_buf(&res_aff, out_bytes, pointSize), 0);

        const auto X = util::BinToDec(out_bytes, coordinateSize);
        const auto Y = util::BinToDec(out_bytes + coordinateSize, coordinateSize);

        ret = {X, Y};
    }

    prj_pt_uninit(&res);
    prj_pt_uninit(&a);

end:

    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::Bignum> libecc::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    nn result, a, b, c;
    int check;
    bitcnt_t blen;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_add(&result, &a, &b), "nn_add error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Sub(A,B)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_cmp(&a, &b, &check), "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_GT(check, 0);

            CF_ASSERT(!nn_sub(&result, &a, &b), "nn_sub error " __FILE__ ":" TOSTRING(__LINE__));
            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Mul(A,B)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_mul(&result, &a, &b), "nn_mul error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Mod(A,B)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_iszero(&b, &check), "nn_iszero error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_EQ(check, 0);

            CF_ASSERT(!nn_mod(&result, &a, &b), "nn_mod error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            /* NOTE: nn_modinv can return an error if there is no modular inverse */
            CF_CHECK_TRUE(!nn_modinv(&result, &a, &b));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("LShift1(A)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_ASSERT(!nn_lshift(&result, &a, 1), "nn_lshift error " __FILE__ ":" TOSTRING(__LINE__));

            CF_ASSERT(!nn_bitlen(&a, &blen), "nn_bitlen error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_LT(blen, NN_MAX_BIT_LEN);

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("RShift(A,B)"):
            {
                std::optional<uint16_t> count;
                CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
                CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
                CF_CHECK_NE(count = libecc_detail::To_uint16_t(op.bn1), std::nullopt);

                CF_ASSERT(!nn_rshift(&result, &a, *count), "nn_rshift error " __FILE__ ":" TOSTRING(__LINE__));

                ret = libecc_detail::To_Component_Bignum(&result);
            }
            break;
        case    CF_CALCOP("GCD(A,B)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_gcd(&result, &a, &b, &check), "nn_gcd error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Sqr(A)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_ASSERT(!nn_sqr(&result, &a), "nn_sqr error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("IsZero(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_ASSERT(!nn_iszero(&a, &check), "nn_iszero error " __FILE__ ":" TOSTRING(__LINE__));

            ret = std::to_string( check );
            break;
        case    CF_CALCOP("IsOne(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_ASSERT(!nn_isone(&a, &check), "nn_isone error " __FILE__ ":" TOSTRING(__LINE__));

            ret = std::to_string( check );
            break;
        case    CF_CALCOP("IsOdd(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_ASSERT(!nn_isodd(&a, &check), "nn_isodd error " __FILE__ ":" TOSTRING(__LINE__));

            ret = std::to_string( check );
            break;
        case    CF_CALCOP("And(A,B)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_and(&result, &a, &b), "nn_and error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Or(A,B)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_or(&result, &a, &b), "nn_or error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Xor(A,B)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));

            CF_ASSERT(!nn_xor(&result, &a, &b), "nn_xor error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("NumBits(A)"):
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));

            CF_ASSERT(!nn_bitlen(&a, &blen), "nn_bitlen error " __FILE__ ":" TOSTRING(__LINE__));

            ret = std::to_string( blen );
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));

            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn2, &c));

            CF_ASSERT(!nn_isodd(&c, &check), "nn_isodd error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(check);

            CF_ASSERT(!nn_cmp(&c, &a, &check), "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_GT(check, 0);
            CF_ASSERT(!nn_cmp(&c, &b, &check), "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_GT(check, 0);

            CF_ASSERT(!nn_mul_mod(&result, &a, &b, &c), "nn_mul_mod error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));

            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn2, &c));

            CF_ASSERT(!nn_cmp(&c, &a, &check), "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_GT(check, 0);
            CF_ASSERT(!nn_cmp(&c, &b, &check), "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_GT(check, 0);

            CF_ASSERT(!nn_mod_add(&result, &a, &b, &c), "nn_mod_add error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            CF_ASSERT(!nn_init(&result, 0), "nn_init error " __FILE__ ":" TOSTRING(__LINE__));

            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));
            CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn2, &c));

            CF_ASSERT(!nn_cmp(&c, &a, &check), "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_GT(check, 0);
            CF_ASSERT(!nn_cmp(&c, &b, &check), "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_GT(check, 0);

            CF_ASSERT(!nn_mod_sub(&result, &a, &b, &c), "nn_mod_sub error " __FILE__ ":" TOSTRING(__LINE__));

            ret = libecc_detail::To_Component_Bignum(&result);
            break;
        case    CF_CALCOP("Bit(A,B)"):
            try {
                CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
                const auto count = boost::lexical_cast<bitcnt_t>(op.bn1.ToTrimmedString());

                u8 bitval;
                CF_ASSERT(!nn_getbit(&a, count, &bitval), "nn_getbit error " __FILE__ ":" TOSTRING(__LINE__));

                ret = std::to_string( bitval );
            } catch ( const boost::bad_lexical_cast &e ) {
            }
            break;
    }

end:

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
