#include "ecdsa_generic.h"
#include "shared.h"
#include "bn_ops.h"
#include <cryptofuzz/util.h>

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
}

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Generic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    wolfCrypt_bignum::Bignum priv(ds);
    ecc_key* key = nullptr;
    ecc_point* pub = nullptr;

    /* Initialize */
    {
        std::optional<int> curveID;
        CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

        CF_CHECK_NE(key = wc_ecc_key_new(nullptr), nullptr);
        CF_CHECK_NE(pub = wc_ecc_new_point_h(nullptr), nullptr);

        CF_CHECK_EQ(wc_ecc_set_curve(key, 0, *curveID), MP_OKAY);
        {
            wolfCrypt_bignum::Bignum priv(&key->k, ds);
            CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);
        }
    }

    /* Process */
    CF_CHECK_EQ(wc_ecc_make_pub(key, pub), MP_OKAY);

    /* Finalize */
    {
        wolfCrypt_bignum::Bignum pub_x(pub->x, ds);
        wolfCrypt_bignum::Bignum pub_y(pub->y, ds);

        std::optional<std::string> pub_x_str, pub_y_str;
        CF_CHECK_NE(pub_x_str = pub_x.ToDecString(), std::nullopt);
        CF_CHECK_NE(pub_y_str = pub_y.ToDecString(), std::nullopt);

        ret = { *pub_x_str, *pub_y_str };
    }

end:
    /* noret */ wc_ecc_key_free(key);
    /* noret */ wc_ecc_del_point(pub);

    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECDSA_Verify_Generic(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ecc_key* key = nullptr;
    std::optional<int> curveID;
    uint8_t* sig = nullptr;
    uint8_t* hash = nullptr;
    word32 sigSz = ECC_MAX_SIG_SIZE;
    int verify;

    {
        try {
            sigSz = ds.Get<uint8_t>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        sig = util::malloc(sigSz);
    }

    CF_CHECK_NE(key = wc_ecc_key_new(nullptr), nullptr);
    {
        const char* name = nullptr;

        CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

        CF_CHECK_NE(name = wc_ecc_get_name(*curveID), nullptr);

        CF_CHECK_EQ(wc_ecc_import_raw(
                    key,
                    util::DecToHex(op.signature.pub.first.ToTrimmedString()).c_str(),
                    util::DecToHex(op.signature.pub.second.ToTrimmedString()).c_str(),
                    nullptr,
                    name), 0);
    }

    CF_CHECK_EQ(wc_ecc_rs_to_sig(
                util::DecToHex(op.signature.signature.first.ToTrimmedString()).c_str(),
                util::DecToHex(op.signature.signature.second.ToTrimmedString()).c_str(),
                sig, &sigSz), 0);

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        CF_CHECK_EQ(wc_ecc_verify_hash(sig, sigSz, op.cleartext.GetPtr(), op.cleartext.GetSize(), &verify, key), 0);
    } else {
        std::optional<wc_HashType> hashType;
        CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);

        const auto hashSize = wc_HashGetDigestSize(*hashType);
        hash = util::malloc(hashSize);

        CF_CHECK_EQ(wc_Hash(*hashType, op.cleartext.GetPtr(), op.cleartext.GetSize(), hash, hashSize), 0);

        CF_CHECK_EQ(wc_ecc_verify_hash(sig, sigSz, hash, hashSize, &verify, key), 0);
    }

    ret = verify ? true : false;

end:
    /* noret */ wc_ecc_key_free(key);

    util::free(sig);
    util::free(hash);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECDSA_Signature> OpECDSA_Sign_Generic(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    if ( op.UseRandomNonce() == false && op.UseSpecifiedNonce() == false ) {
        return ret;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ecc_key* key = nullptr;
    ecc_point* pub = nullptr;
    std::optional<int> curveID;
    uint8_t* sig = nullptr;
    word32 sigSz = ECC_MAX_SIG_SIZE;
    uint8_t* hash = nullptr;
    wolfCrypt_bignum::Bignum nonce(ds), r(ds), s(ds);

    CF_CHECK_NE(op.priv.ToTrimmedString(), "0");
    CF_CHECK_NE(key = wc_ecc_key_new(nullptr), nullptr);
    CF_CHECK_NE(pub = wc_ecc_new_point_h(nullptr), nullptr);

    {
        try {
            sigSz = ds.Get<uint8_t>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        sig = util::malloc(sigSz);
    }

    {
        const char* name = nullptr;

        CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

        CF_CHECK_NE(name = wc_ecc_get_name(*curveID), nullptr);
        CF_CHECK_EQ(wc_ecc_set_curve(key, 0, *curveID), 0);

        wolfCrypt_bignum::Bignum priv(&key->k, ds);
        CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);
        key->type = ECC_PRIVATEKEY_ONLY;

        if ( op.UseSpecifiedNonce() == true ) {
            CF_CHECK_EQ(nonce.Set(op.nonce.ToString(ds)), true);

            const size_t nonce_bytes_size = mp_unsigned_bin_size(nonce.GetPtr());

            /* Convert nonce to byte array */
            nonce_bytes = util::malloc(nonce_bytes_size);
            CF_CHECK_EQ(mp_to_unsigned_bin(nonce.GetPtr(), nonce_bytes), 0);

            /* Set nonce */
            CF_CHECK_EQ(wc_ecc_sign_set_k(nonce_bytes, nonce_bytes_size, key), 0);
        }

        CF_CHECK_EQ(wc_ecc_make_pub(key, pub), 0);
    }

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        CF_CHECK_EQ(wc_ecc_sign_hash(op.cleartext.GetPtr(), op.cleartext.GetSize(), sig, &sigSz, &wolfCrypt_detail::rng, key), 0);
    } else {
        std::optional<wc_HashType> hashType;
        CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);

        const auto hashSize = wc_HashGetDigestSize(*hashType);
        hash = util::malloc(hashSize);

        CF_CHECK_EQ(wc_Hash(*hashType, op.cleartext.GetPtr(), op.cleartext.GetSize(), hash, hashSize), 0);

        CF_CHECK_EQ(wc_ecc_sign_hash(hash, hashSize, sig, &sigSz, &wolfCrypt_detail::rng, key), 0);
    }

    CF_CHECK_EQ(DecodeECC_DSA_Sig(sig, sigSz, r.GetPtr(), s.GetPtr()), 0);
    {
        std::optional<std::string> pub_x_str, pub_y_str, r_str, s_str;

        if ( op.curveType.Get() == CF_ECC_CURVE("secp256k1") ) {
            wolfCrypt_bignum::Bignum SMax(ds);
            CF_CHECK_EQ(SMax.Set("57896044618658097711785492504343953926418782139537452191302581570759080747168"), true);
            if ( mp_cmp(s.GetPtr(), SMax.GetPtr()) == 1 ) {
                wolfCrypt_bignum::Bignum SSub(ds);
                CF_CHECK_EQ(SSub.Set("115792089237316195423570985008687907852837564279074904382605163141518161494337"), true);
                CF_CHECK_EQ(mp_sub(SSub.GetPtr(), s.GetPtr(), s.GetPtr()), 0);
            }
        }

        CF_CHECK_NE(r_str = r.ToDecString(), std::nullopt);
        CF_CHECK_NE(s_str = s.ToDecString(), std::nullopt);

        {
            wolfCrypt_bignum::Bignum pub_x(pub->x, ds);
            wolfCrypt_bignum::Bignum pub_y(pub->y, ds);

            CF_CHECK_NE(pub_x_str = pub_x.ToDecString(), std::nullopt);
            CF_CHECK_NE(pub_y_str = pub_y.ToDecString(), std::nullopt);
        }

        ret = component::ECDSA_Signature({*r_str, *s_str}, {*pub_x_str, *pub_y_str});
    }
end:

    util::free(sig);
    util::free(hash);

    /* noret */ wc_ecc_key_free(key);
    /* noret */ wc_ecc_del_point(pub);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
