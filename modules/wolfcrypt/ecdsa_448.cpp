#include "ecdsa_448.h"
#include "module_internal.h"
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

#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
    extern bool haveAllocFailure;
#endif

static bool ed448LoadPrivateKey(ed448_key& key, component::Bignum priv, Datasource& ds) {
    bool ret = false;

    uint8_t priv_bytes[ED448_KEY_SIZE];

    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, priv, priv_bytes, sizeof(priv_bytes)), true);
    CF_CHECK_EQ(wc_ed448_import_private_only(priv_bytes, sizeof(priv_bytes), &key), 0);

    ret = true;
end:
    return ret;
}

static std::optional<std::vector<uint8_t>> ed448GetPublicKeyAsVector(ed448_key& key) {
    std::optional<std::vector<uint8_t>> ret = std::nullopt;
    uint8_t pub_bytes[ED448_PUB_KEY_SIZE];

    WC_CHECK_EQ(wc_ed448_make_public(&key, pub_bytes, sizeof(pub_bytes)), MP_OKAY);

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

static bool ed448LoadPublicKey(ed448_key& key, component::Bignum pub, Datasource& ds, const bool mustSucceed = false) {
    bool ret = false;

    uint8_t pub_bytes[ED448_PUB_KEY_SIZE];
    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, pub, pub_bytes, sizeof(pub_bytes), mustSucceed), true);
    CF_CHECK_EQ(wc_ed448_import_public(pub_bytes, sizeof(pub_bytes), &key), 0);

    ret = true;
end:
    return ret;
}

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Curve448(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    static const uint8_t basepoint[CURVE448_KEY_SIZE] = {5};

    std::optional<std::vector<uint8_t>> priv_bytes = std::nullopt;
    uint8_t pub_bytes[CURVE448_PUB_KEY_SIZE];

    /* Load private key */
    {
        priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), CURVE448_KEY_SIZE);
        CF_CHECK_NE(priv_bytes, std::nullopt);

        priv_bytes->data()[0] &= 0xFC;
        priv_bytes->data()[55] |= 0x80; static_assert(55 < CURVE448_KEY_SIZE);
    }

    /* Convert to public key */
    {
        CF_CHECK_EQ(curve448(pub_bytes, priv_bytes->data(), basepoint), MP_OKAY);
    }

    /* Convert public key */
    {
        ret = { util::BinToDec(pub_bytes, sizeof(pub_bytes)), "0" };
    }

end:
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Ed448(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t pub_bytes[ED448_PUB_KEY_SIZE];

    ed448_key key;
    bool e448_key_inited = false;

    WC_CHECK_EQ(wc_ed448_init(&key), 0);
    e448_key_inited = true;

    /* Load private key */
    {
        const auto priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), ED448_KEY_SIZE);
        CF_CHECK_NE(priv_bytes, std::nullopt);

        WC_CHECK_EQ(wc_ed448_import_private_only(priv_bytes->data(), priv_bytes->size(), &key), 0);
    }

    /* Convert to public key */
    {
        WC_CHECK_EQ(wc_ed448_make_public(&key, pub_bytes, sizeof(pub_bytes)), MP_OKAY);
    }

    /* Convert public key */
    {
        ret = { util::BinToDec(pub_bytes, sizeof(pub_bytes)), "0" };
    }

end:
    if ( e448_key_inited == true ) {
        wc_ed448_free(&key);
    }

    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECC_ValidatePubkey_Ed448(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ed448_key key;
    bool e448_key_inited = false;

    WC_CHECK_EQ(wc_ed448_init(&key), 0);
    e448_key_inited = true;

    CF_CHECK_EQ(ed448LoadPublicKey(key, op.pub.first, ds), true);

    haveAllocFailure = false;
    ret = wc_ed448_check_key(&key) == 0;
    if ( *ret == false && haveAllocFailure == true ) {
        ret = std::nullopt;
    }

end:
    if ( e448_key_inited == true ) {
        wc_ed448_free(&key);
    }

    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECC_ValidatePubkey_Curve448(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    wolfCrypt_bignum::Bignum pub(ds);
    uint8_t pub_bytes[CURVE448_KEY_SIZE];

    CF_CHECK_EQ(pub.Set(op.pub.first.ToString(ds)), true);
    CF_CHECK_TRUE(pub.ToBin(pub_bytes, sizeof(pub_bytes)));

    haveAllocFailure = false;
    ret = wc_curve448_check_public(pub_bytes, sizeof(pub_bytes), EC448_BIG_ENDIAN) == 0;
    if ( *ret == false && haveAllocFailure == true ) {
        ret = std::nullopt;
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
    bool e448_key_inited = false;
    uint8_t sig[ED448_SIG_SIZE];
    word32 sigSz = sizeof(sig);

    WC_CHECK_EQ(wc_ed448_init(&key), 0);
    e448_key_inited = true;

    CF_CHECK_EQ(wolfCrypt_detail::ed448LoadPrivateKey(key, op.priv, ds), true);
    CF_CHECK_EQ(wolfCrypt_detail::ed448DerivePublicKey(key), true);

    /* Sign message */
    WC_CHECK_EQ(wc_ed448_sign_msg(op.cleartext.GetPtr(), op.cleartext.GetSize(), sig, &sigSz, &key, nullptr, 0), MP_OKAY);
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
    if ( e448_key_inited == true ) {
        wc_ed448_free(&key);
    }

    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECDSA_Verify_ed448(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    ed448_key key;
    bool e448_key_inited = false;
    uint8_t ed448sig[ED448_SIG_SIZE];
    int verify;
    bool oneShot = true;
    bool haveEmptyPart = false;

    haveAllocFailure = false;
    ret = false;

    WC_CHECK_EQ(wc_ed448_init(&key), 0);
    e448_key_inited = true;

    CF_CHECK_EQ(ed448LoadPublicKey(key, op.signature.pub.first, ds, true), true);
    CF_CHECK_EQ(wolfCrypt_bignum::Bignum::ToBin(ds, op.signature.signature, ed448sig, sizeof(ed448sig), true), true);

#if defined(WOLFSSL_ED25519_STREAMING_VERIFY)
    try { oneShot = ds.Get<bool>(); } catch ( ... ) { }
#endif

    if ( oneShot == true ) {
        WC_CHECK_EQ(wc_ed448_verify_msg(ed448sig, sizeof(ed448sig), op.cleartext.GetPtr(), op.cleartext.GetSize(), &verify, &key, nullptr, 0), 0);
    } else {
#if !defined(WOLFSSL_ED25519_STREAMING_VERIFY)
        CF_UNREACHABLE();
#else
        const auto parts = util::ToParts(ds, op.cleartext);

        WC_CHECK_EQ(wc_ed448_verify_msg_init(ed448sig, sizeof(ed448sig), &key, (byte)Ed448, nullptr, 0), 0);

        for (const auto& part : parts) {
            if ( part.second == 0 ) {
                haveEmptyPart = true;
            }
            WC_CHECK_EQ(wc_ed448_verify_msg_update(part.first, part.second, &key), 0);
        }

        WC_CHECK_EQ(wc_ed448_verify_msg_final(ed448sig, sizeof(ed448sig), &verify, &key), 0);
#endif
    }

    ret = verify ? true : false;

end:
    if ( e448_key_inited == true ) {
        wc_ed448_free(&key);
    }

    wolfCrypt_detail::UnsetGlobalDs();

    if ( ret && *ret == false ) {
        if ( haveAllocFailure ) {
            ret = std::nullopt;
        } else if ( haveEmptyPart ) {
            ret = std::nullopt;
        } else if ( op.cleartext.IsZero() ) {
            ret = std::nullopt;
        }

    }
    return ret;
}

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
