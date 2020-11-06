#include "ecdsa_448.h"
#include "shared.h"
#include "bn_ops.h"
#include <cryptofuzz/util.h>

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/ed448.h>
}

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {

static bool ed448LoadPrivateKey(ed448_key& key, component::Bignum priv, Datasource& ds) {
    bool ret = false;

    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, priv, key.k, sizeof(key.k)), true);

    ret = true;
end:
    return ret;
}

static std::optional<std::vector<uint8_t>> ed448GetPublicKeyAsVector(ed448_key& key) {
    std::optional<std::vector<uint8_t>> ret = std::nullopt;
    uint8_t pub_bytes[ED448_PUB_KEY_SIZE];

    CF_CHECK_EQ(wc_ed448_make_public(&key, pub_bytes, sizeof(pub_bytes)), MP_OKAY);

    ret = std::vector<uint8_t>(pub_bytes, pub_bytes + sizeof(pub_bytes));
end:
    return ret;
}

static std::optional<component::ECC_PublicKey> ed448GetPublicKey(ed448_key& key, Datasource& ds) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    std::optional<std::vector<uint8_t>> pubv = std::nullopt;
    std::optional<component::Bignum> pub = std::nullopt;

    CF_CHECK_NE(pubv = ed448GetPublicKeyAsVector(key), std::nullopt);
    CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pubv->data(), pubv->size()), std::nullopt);

    ret = {pub->ToString(), "0"};

end:
    return ret;
}

static bool ed448DerivePublicKey(ed448_key& key) {
    std::optional<std::vector<uint8_t>> pubv = std::nullopt;
    bool ret = false;

    CF_CHECK_NE(pubv = ed448GetPublicKeyAsVector(key), std::nullopt);
    memcpy(key.p, pubv->data(), ED448_PUB_KEY_SIZE);
    key.pubKeySet = 1;

    ret = true;

end:
    return ret;
}

static bool ed448LoadPublicKey(ed448_key& key, component::Bignum pub, Datasource& ds) {
    bool ret = false;

    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, pub, key.p, sizeof(key.p)), true);
    key.pubKeySet = 1;

    ret = true;
end:
    return ret;
}

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Curve448(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    static const uint8_t basepoint[CURVE448_KEY_SIZE] = {5};

    wolfCrypt_bignum::Bignum priv(ds), pub(ds);
    uint8_t pub_bytes[CURVE448_KEY_SIZE];
    uint8_t priv_bytes[CURVE448_KEY_SIZE];

    /* Load private key */
    {
        CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);
        CF_CHECK_EQ(mp_to_unsigned_bin_len(priv.GetPtr(), priv_bytes, sizeof(priv_bytes)), MP_OKAY);
        priv_bytes[0] &= 0xFC;
        priv_bytes[55] |= 0x80;
    }

    /* Convert to public key */
    {
        CF_CHECK_EQ(curve448(pub_bytes, priv_bytes, basepoint), MP_OKAY);
    }

    /* Convert public key */
    {
        std::optional<std::string> pub_x_str;
        CF_CHECK_EQ(mp_read_unsigned_bin(pub.GetPtr(), pub_bytes, sizeof(pub_bytes)), MP_OKAY);
        CF_CHECK_NE(pub_x_str = pub.ToDecString(), std::nullopt);
        ret = { *pub_x_str, "0" };
    }

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Ed448(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    wolfCrypt_bignum::Bignum priv(ds), pub(ds);
    uint8_t pub_bytes[ED448_PUB_KEY_SIZE];

    ed448_key key;

    /* Load private key */
    {
        CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);
        CF_CHECK_EQ(mp_to_unsigned_bin_len(priv.GetPtr(), key.k, sizeof(key.k)), MP_OKAY);
    }

    /* Convert to public key */
    {
        CF_CHECK_EQ(wc_ed448_make_public(&key, pub_bytes, sizeof(pub_bytes)), MP_OKAY);
    }

    /* Convert public key */
    {
        std::optional<std::string> pub_x_str;
        CF_CHECK_EQ(mp_read_unsigned_bin(pub.GetPtr(), pub_bytes, sizeof(pub_bytes)), MP_OKAY);
        CF_CHECK_NE(pub_x_str = pub.ToDecString(), std::nullopt);
        ret = { *pub_x_str, "0" };
    }

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<component::ECDSA_Signature> OpECDSA_Sign_ed448(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ed448_key key;
    uint8_t sig[ED448_SIG_SIZE];
    word32 sigSz = sizeof(sig);

    memset(&key, 0, sizeof(key));

    CF_CHECK_EQ(wolfCrypt_detail::ed448LoadPrivateKey(key, op.priv, ds), true);
    CF_CHECK_EQ(wolfCrypt_detail::ed448DerivePublicKey(key), true);

    /* Sign message */
    CF_CHECK_EQ(wc_ed448_sign_msg(op.cleartext.GetPtr(), op.cleartext.GetSize(), sig, &sigSz, &key, nullptr, 0), MP_OKAY);
    CF_CHECK_EQ(sigSz, ED448_SIG_SIZE);
    static_assert(ED448_SIG_SIZE % 2 == 0);

    {
        std::optional<component::BignumPair> ret_sig;
        std::optional<component::BignumPair> ret_pub;

        CF_CHECK_NE(ret_sig = wolfCrypt_bignum::Bignum::BinToBignumPair(ds, sig, ED448_SIG_SIZE), std::nullopt);
        CF_CHECK_NE(ret_pub = wolfCrypt_detail::ed448GetPublicKey(key, ds), std::nullopt);

        ret = component::ECDSA_Signature(*ret_sig, *ret_pub);
    }

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECDSA_Verify_ed448(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ed448_key key;
    uint8_t ed448sig[ED448_SIG_SIZE];
    int verify;

    memset(&key, 0, sizeof(key));

    CF_CHECK_EQ(ed448LoadPublicKey(key, op.signature.pub.first, ds), true);
    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, op.signature.signature, ed448sig, sizeof(ed448sig)), true);
    CF_CHECK_EQ(wc_ed448_verify_msg(ed448sig, sizeof(ed448sig), op.cleartext.GetPtr(), op.cleartext.GetSize(), &verify, &key, nullptr, 0), 0);

    ret = verify ? true : false;

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
