#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <boost/lexical_cast.hpp>

extern "C" {
    #include <libsig.h>
    #include <hash/hmac.h>
}

namespace cryptofuzz {
namespace module {
namespace libecc_detail {
    Datasource* global_ds = nullptr;
    FILE* fp_dev_urandom = nullptr;
    const ec_sig_mapping *sm_ecdsa, *sm_ecgdsa, *sm_ecrdsa;

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
            case    CF_DIGEST("SM3"):
                return get_hash_by_type(SM3);
            case    CF_DIGEST("SHAKE256_114"):
                return get_hash_by_type(SHAKE256);
            case    CF_DIGEST("STREEBOG-256"):
                return get_hash_by_type(STREEBOG256);
            case    CF_DIGEST("STREEBOG-512"):
                return get_hash_by_type(STREEBOG512);
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
    CF_ASSERT((libecc_detail::sm_ecdsa = get_sig_by_name("ECDSA")) != nullptr, "Cannot initialize ECDSA");
    CF_ASSERT((libecc_detail::sm_ecgdsa = get_sig_by_name("ECGDSA")) != nullptr, "Cannot initialize ECGDSA");
    CF_ASSERT((libecc_detail::sm_ecrdsa = get_sig_by_name("ECRDSA")) != nullptr, "Cannot initialize ECRDSA");

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

std::optional<component::MAC> libecc::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool oneShot = false;
    uint8_t outlen = 0;
    uint8_t* out = nullptr;
    std::optional<hash_alg_type> hash;

    CF_CHECK_NE(hash = libecc_detail::To_hash_alg_type(op.digestType.Get()), std::nullopt);

    try {
        outlen = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    try {
        oneShot = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    out = util::malloc(outlen);

    if ( oneShot == true ) {
        CF_INSTALL_JMP();

        CF_CHECK_EQ(hmac(
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    *hash,
                    op.cleartext.GetPtr(),
                    op.cleartext.GetSize(),
                    out, &outlen
                    ), 0);

        ret = component::Digest(out, outlen);
    } else {
        CF_INSTALL_JMP();

        hmac_context ctx;

        /* Initialize */
        CF_CHECK_EQ(hmac_init(
                    &ctx,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    *hash), 0);

        {
            const auto parts = util::ToParts(ds, op.cleartext);

            for (const auto& part : parts) {
                if ( part.first == nullptr ) {
                    continue;
                }

                CF_CHECK_EQ(hmac_update(&ctx, part.first, part.second), 0);
            }
        }

        /* Finalize */
        {
            CF_CHECK_EQ(hmac_finalize(&ctx, out, &outlen), 0);
            ret = component::Digest(out, outlen);
        }
    }

end:
    CF_RESTORE_JMP();

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
    std::string priv_str;
    aff_pt Q_aff;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(curveType), nullptr);
    CF_NORET(import_params(&params, curve_params));

    sig_type = libecc_detail::sm_ecdsa->type;

    priv_str = _priv.ToTrimmedString();
    CF_CHECK_NE(priv_str, "0");
    CF_CHECK_NE(priv_str, *cryptofuzz::repository::ECC_CurveToOrder(curveType.Get()));
    CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str), std::nullopt);
    CF_CHECK_LTE(priv_bytes->size(), NN_MAX_BYTE_LEN);

    CF_INSTALL_JMP();

    CF_NORET(ec_priv_key_import_from_buf(&priv, &params, priv_bytes->data(), priv_bytes->size(), sig_type));
    memset(&pub, 0, sizeof(pub));
    CF_CHECK_EQ(init_pubkey_from_privkey(&pub, &priv), 0);
    CF_CHECK_EQ(pub.magic, PUB_KEY_MAGIC);

    prj_pt_to_aff(&Q_aff, &pub.y);
    ec_shortw_aff_to_prj(&pub.y, &Q_aff);

    {
        const auto _ret = libecc_detail::To_Component_BignumPair(pub);
        CF_CHECK_TRUE(_priv.IsLessThan(*cryptofuzz::repository::ECC_CurveToOrder(curveType.Get())));
        ret = _ret;
    }

end:
    CF_RESTORE_JMP();

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
    typedef int (*ecxdsa_rfc6979_sign_finalize_t)(struct ec_sign_context *ctx, u8 *sig, u8 siglen, ec_sig_alg_type key_type);

    template <class Operation, ec_sig_alg_type AlgType>
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
        const ec_sig_alg_type alg = op.UseRFC6979Nonce() ? DECDSA : AlgType;

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

        CF_INSTALL_JMP();

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
        CF_RESTORE_JMP();

        util::free(signature);

        libecc_detail::global_ds = nullptr;
        return ret;
    }

    typedef int (*ecxdsa_verify_raw_t)(struct ec_verify_context *ctx, const u8 *input, u8 inputlen);
    typedef int (*ecxdsa_verify_update_t)(struct ec_verify_context *ctx, const u8 *chunk, u32 chunklen);
    typedef int (*ecxdsa_verify_finalize_t)(struct ec_verify_context *ctx);

    template <class Operation, ec_sig_alg_type AlgType>
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

            CF_INSTALL_JMP();

            CF_CHECK_EQ(ec_pub_key_import_from_buf(
                        &kp.pub_key,
                        &params,
                        pub.data(), pub.size(),
                        sm->type), 0);

            CF_CHECK_EQ(prj_pt_is_on_curve(&kp.pub_key.y), 1);
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
        CF_RESTORE_JMP();

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
    CF_NORET(import_params(&params, curve_params));

    CF_INSTALL_JMP();

    prj_pt_init(&res, &(params.ec_curve));

    {
        fp_init_from_buf(&x, &(params.ec_fp), ax_bin->data(), ax_bin->size());

        fp_init_from_buf(&y, &(params.ec_fp), ay_bin->data(), ay_bin->size());

        fp_init(&z, &(params.ec_fp));
        fp_one(&z);

        prj_pt_init_from_coords(&a, &(params.ec_curve), &x, &y, &z);

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    {
        fp_init_from_buf(&x, &(params.ec_fp), bx_bin->data(), bx_bin->size());

        fp_init_from_buf(&y, &(params.ec_fp), by_bin->data(), by_bin->size());

        fp_init(&z, &(params.ec_fp));
        fp_one(&z);

        prj_pt_init_from_coords(&b, &(params.ec_curve), &x, &y, &z);

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    prj_pt_add(&res, &a, &b);

    prj_pt_to_aff(&res_aff, &res);

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
    CF_RESTORE_JMP();

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
    bool useMonty = false;

    libecc_detail::global_ds = &ds;

    try {
        useMonty = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    const auto ax_bin = util::DecToBin(op.a.first.ToTrimmedString());
    const auto ay_bin = util::DecToBin(op.a.second.ToTrimmedString());

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_NORET(import_params(&params, curve_params));

    CF_INSTALL_JMP();

    prj_pt_init(&res, &(params.ec_curve));

    {
        fp_init_from_buf(&x, &(params.ec_fp), ax_bin->data(), ax_bin->size());

        fp_init_from_buf(&y, &(params.ec_fp), ay_bin->data(), ay_bin->size());

        fp_init(&z, &(params.ec_fp));
        fp_one(&z);

        prj_pt_init_from_coords(&a, &(params.ec_curve), &x, &y, &z);

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    CF_CHECK_TRUE(libecc_detail::To_nn_t(op.b, &b));

    if ( useMonty == false ) {
        prj_pt_mul(&res, &b, &a);
    } else {
        prj_pt_mul_monty(&res, &b, &a);
    }

    prj_pt_to_aff(&res_aff, &res);

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
    CF_RESTORE_JMP();

    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a;
    aff_pt res_aff;
    fp x, y, z;

    const auto ax_bin = util::DecToBin(op.a.first.ToTrimmedString());
    const auto ay_bin = util::DecToBin(op.a.second.ToTrimmedString());

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_NORET(import_params(&params, curve_params));

    CF_INSTALL_JMP();

    prj_pt_init(&res, &(params.ec_curve));

    {
        fp_init_from_buf(&x, &(params.ec_fp), ax_bin->data(), ax_bin->size());

        fp_init_from_buf(&y, &(params.ec_fp), ay_bin->data(), ay_bin->size());

        fp_init(&z, &(params.ec_fp));
        fp_one(&z);

        prj_pt_init_from_coords(&a, &(params.ec_curve), &x, &y, &z);

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    prj_pt_neg(&res, &a);

    prj_pt_to_aff(&res_aff, &res);

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
    CF_RESTORE_JMP();

    return ret;
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a;
    aff_pt res_aff;
    fp x, y, z;

    const auto ax_bin = util::DecToBin(op.a.first.ToTrimmedString());
    const auto ay_bin = util::DecToBin(op.a.second.ToTrimmedString());

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_NORET(import_params(&params, curve_params));

    CF_INSTALL_JMP();

    prj_pt_init(&res, &(params.ec_curve));

    {
        fp_init_from_buf(&x, &(params.ec_fp), ax_bin->data(), ax_bin->size());

        fp_init_from_buf(&y, &(params.ec_fp), ay_bin->data(), ay_bin->size());

        fp_init(&z, &(params.ec_fp));
        fp_one(&z);

        prj_pt_init_from_coords(&a, &(params.ec_curve), &x, &y, &z);

        fp_uninit(&x);
        fp_uninit(&y);
        fp_uninit(&z);
    }

    prj_pt_dbl(&res, &a);

    prj_pt_to_aff(&res_aff, &res);

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
    CF_RESTORE_JMP();

    return ret;
}

std::optional<component::Bignum> libecc::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

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
            {
                CF_NORET(nn_init(&result, 0));

                CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn0, &a));
                CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn1, &b));
                CF_CHECK_TRUE(libecc_detail::To_nn_t(op.bn2, &c));

                CF_CHECK_GT(nn_cmp(&c, &a), 0);
                CF_CHECK_GT(nn_cmp(&c, &b), 0);

                bool mod_inc = false;

                if ( op.bn1.ToTrimmedString() == "1") {
                    try {
                        mod_inc = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }

                if ( mod_inc == false ) {
                    CF_NORET(nn_mod_add(&result, &a, &b, &c));
                } else {
                    CF_NORET(nn_mod_inc(&result, &a, &c));
                }

                ret = libecc_detail::To_Component_Bignum(&result);
            }
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
        case    CF_CALCOP("LRot(A,B,C)"):
            {
                CF_NORET(nn_init(&result, 0));

                std::optional<uint16_t> count, bitlen;

                CF_CHECK_NE(count = libecc_detail::To_uint16_t(op.bn1), std::nullopt);
                CF_CHECK_NE(bitlen = libecc_detail::To_uint16_t(op.bn2), std::nullopt);

                CF_NORET(nn_lrot(&result, &a, *count, *bitlen));

                ret = libecc_detail::To_Component_Bignum(&result);
            }
            break;
        case    CF_CALCOP("RRot(A,B,C)"):
            {
                CF_NORET(nn_init(&result, 0));

                std::optional<uint16_t> count, bitlen;

                CF_CHECK_NE(count = libecc_detail::To_uint16_t(op.bn1), std::nullopt);
                CF_CHECK_NE(bitlen = libecc_detail::To_uint16_t(op.bn2), std::nullopt);

                CF_NORET(nn_rrot(&result, &a, *count, *bitlen));

                ret = libecc_detail::To_Component_Bignum(&result);
            }
            break;
    }

end:
    CF_RESTORE_JMP();

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
