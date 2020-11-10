#include "ecdsa_25519.h"
#include "shared.h"
#include "bn_ops.h"
#include <cryptofuzz/util.h>

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
}

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {

static bool ed25519LoadPrivateKey(ed25519_key& key, component::Bignum priv, Datasource& ds) {
    bool ret = false;

    static_assert(sizeof(key.k) == 64);
    memset(key.k + 32, 0, 32);
    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, priv, key.k, 32), true);

    ret = true;
end:
    return ret;
}

static bool ed25519LoadPublicKey(ed25519_key& key, component::Bignum pub, Datasource& ds) {
    bool ret = false;

    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, pub, key.p, sizeof(key.p)), true);
    key.pubKeySet = 1;

    ret = true;
end:
    return ret;
}

static std::optional<std::vector<uint8_t>> ed25519GetPublicKeyAsVector(ed25519_key& key) {
    std::optional<std::vector<uint8_t>> ret = std::nullopt;
    uint8_t pub_bytes[ED25519_PUB_KEY_SIZE];

    CF_CHECK_EQ(wc_ed25519_make_public(&key, pub_bytes, sizeof(pub_bytes)), MP_OKAY);

    ret = std::vector<uint8_t>(pub_bytes, pub_bytes + sizeof(pub_bytes));
end:
    return ret;
}

static std::optional<component::ECC_PublicKey> ed25519GetPublicKey(ed25519_key& key, Datasource& ds) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    std::optional<std::vector<uint8_t>> pubv = std::nullopt;
    std::optional<component::Bignum> pub = std::nullopt;

    CF_CHECK_NE(pubv = ed25519GetPublicKeyAsVector(key), std::nullopt);
    CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pubv->data(), pubv->size()), std::nullopt);

    ret = {pub->ToString(), "0"};

end:
    return ret;
}

static bool ed25519DerivePublicKey(ed25519_key& key) {
    std::optional<std::vector<uint8_t>> pubv = std::nullopt;
    bool ret = false;

    CF_CHECK_NE(pubv = ed25519GetPublicKeyAsVector(key), std::nullopt);
    memcpy(key.p, pubv->data(), ED25519_PUB_KEY_SIZE);
    key.pubKeySet = 1;

    ret = true;

end:
    return ret;
}

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Curve25519(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    wolfCrypt_bignum::Bignum priv(ds), pub(ds);
    uint8_t pub_bytes[CURVE25519_KEYSIZE];
    uint8_t priv_bytes[CURVE25519_KEYSIZE];

    /* Load private key */
    {
        CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);
        CF_CHECK_EQ(mp_to_unsigned_bin_len(priv.GetPtr(), priv_bytes, sizeof(priv_bytes)), MP_OKAY);
        priv_bytes[0] &= 248;
        priv_bytes[31] &= 127;
        priv_bytes[31] |= 64;
    }

    /* Convert to public key */
    {
        CF_CHECK_EQ(wc_curve25519_make_pub(sizeof(pub_bytes), pub_bytes, sizeof(priv_bytes), priv_bytes), MP_OKAY);
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

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Ed25519(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    wolfCrypt_bignum::Bignum priv(ds), pub(ds);

    ed25519_key key;

    CF_CHECK_EQ(ed25519LoadPrivateKey(key, op.priv, ds), true);
    ret = ed25519GetPublicKey(key, ds);

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<component::ECDSA_Signature> OpECDSA_Sign_ed25519(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ed25519_key key;
    uint8_t sig[ED25519_SIG_SIZE];
    word32 sigSz = sizeof(sig);

    memset(&key, 0, sizeof(key));

    CF_CHECK_EQ(wolfCrypt_detail::ed25519LoadPrivateKey(key, op.priv, ds), true);
    CF_CHECK_EQ(wolfCrypt_detail::ed25519DerivePublicKey(key), true);

    /* Sign message */
    CF_CHECK_EQ(wc_ed25519_sign_msg(op.cleartext.GetPtr(), op.cleartext.GetSize(), sig, &sigSz, &key), MP_OKAY);
    CF_CHECK_EQ(sigSz, ED25519_SIG_SIZE);
    static_assert(ED25519_SIG_SIZE % 2 == 0);

    {
        std::optional<component::BignumPair> ret_sig;
        std::optional<component::BignumPair> ret_pub;

        CF_CHECK_NE(ret_sig = wolfCrypt_bignum::Bignum::BinToBignumPair(ds, sig, ED25519_SIG_SIZE), std::nullopt);
        CF_CHECK_NE(ret_pub = wolfCrypt_detail::ed25519GetPublicKey(key, ds), std::nullopt);

        ret = component::ECDSA_Signature(*ret_sig, *ret_pub);
    }

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECDSA_Verify_ed25519(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ed25519_key key;
    uint8_t ed25519sig[ED25519_SIG_SIZE];
    int verify;

    memset(&key, 0, sizeof(key));

    CF_CHECK_EQ(ed25519LoadPublicKey(key, op.signature.pub.first, ds), true);
    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, op.signature.signature, ed25519sig, sizeof(ed25519sig)), true);
    CF_CHECK_EQ(wc_ed25519_verify_msg(ed25519sig, sizeof(ed25519sig), op.cleartext.GetPtr(), op.cleartext.GetSize(), &verify, &key), 0);

    ret = verify ? true : false;

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
