#include "ecdsa_generic.h"
#include "shared.h"
#include "bn_ops.h"
#include <cryptofuzz/util.h>
#include <iostream>

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {

#if !defined(WOLFSSL_SP_MATH)
#include "custom_curves.h"
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
    extern bool haveAllocFailure;
#endif

WC_RNG* GetRNG(void);

ECCKey::ECCKey(Datasource& ds) :
    ds(ds) {
    if ( (key = wc_ecc_key_new(nullptr)) == nullptr ) {
        throw std::exception();
    }
}

ECCKey::~ECCKey() {
    CF_NORET(wc_ecc_key_free(key));
}

ecc_key* ECCKey::GetPtr(void) {
    uint8_t* x963 = nullptr;
    ecc_key* newKey = nullptr;

    bool exportToX963 = false;
    try {
        exportToX963 = ds.Get<bool>();
    } catch ( ... ) { }

    if ( exportToX963 == true ) {
        CF_CHECK_NE(newKey = wc_ecc_key_new(nullptr), nullptr);

        word32 outLen;

        bool compressed = false;
        try { compressed  = ds.Get<bool>();} catch ( ... ) { }

        CF_CHECK_EQ(wc_ecc_export_x963_ex(key, nullptr, &outLen, compressed), LENGTH_ONLY_E);
        x963 = util::malloc(outLen);
        CF_CHECK_EQ(wc_ecc_export_x963_ex(key, x963, &outLen, compressed), 0);;

        /* Get the curve id of the old key */
        int curveID;
        CF_CHECK_NE(curveID = wc_ecc_get_curve_id(key->idx), ECC_CURVE_INVALID);

        haveAllocFailure = false;
        CF_ASSERT(wc_ecc_import_x963_ex(x963, outLen, newKey, curveID) == 0 || haveAllocFailure, "Cannot import X963-exported ECC key");

        CF_NORET(wc_ecc_key_free(key));
        key = newKey;
        newKey = nullptr;
    }

end:
    util::free(x963);
    CF_NORET(wc_ecc_key_free(newKey));

    return key;
}

bool ECCKey::SetCurve(const Type& curveType) {
    bool ret = false;

#if !defined(WOLFSSL_SP_MATH)
    bool useCustomCurve = false;

    try {
        useCustomCurve = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    if ( useCustomCurve == false )
#endif
    {
#if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
        std::cout << "Using native curve" << std::endl;
#endif
        std::optional<int> curveID;

        CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(curveType), std::nullopt);
        this->curveID = *curveID;

        CF_CHECK_EQ(wc_ecc_set_curve(GetPtr(), 0, *curveID), 0);
    }
#if !defined(WOLFSSL_SP_MATH)
    else {
 #if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
        std::cout << "Using custom curve" << std::endl;
 #endif
        const ecc_set_type* curveSpec;
        CF_CHECK_NE(curveSpec = GetCustomCurve(curveType.Get()), nullptr);
        CF_CHECK_EQ(wc_ecc_set_custom_curve(GetPtr(), curveSpec), 0);
        this->curveID = ECC_CURVE_CUSTOM;
    }
#endif

    ret = true;

end:
    return ret;
}

bool ECCKey::LoadPrivateKey(const component::Bignum& priv) {
    bool ret = false;
    std::optional<std::vector<uint8_t>> priv_bytes;

    CF_CHECK_NE(priv_bytes = wolfCrypt_bignum::Bignum::ToBin(ds, priv), std::nullopt);

    CF_CHECK_EQ(wc_ecc_import_private_key_ex(priv_bytes->data(), priv_bytes->size(), nullptr, 0, GetPtr(), *curveID), 0);

    ret = true;

end:
    return ret;
}

std::optional<ECCPoint> ECCKey::MakePub(void) {
    std::optional<ECCPoint> ret = std::nullopt;

    ECCPoint pub(ds, *curveID);
    CF_CHECK_EQ(wc_ecc_make_pub(GetPtr(), pub.GetPtr()), 0);
    pub.SetInitialized();

    return pub;

end:
    return ret;
}

bool ECCKey::SetRNG(void) {
    bool ret = false;

    CF_CHECK_EQ(wc_ecc_set_rng(GetPtr(), wolfCrypt_detail::GetRNG()), 0);

    ret = true;
end:
    return ret;
}

ECCPoint::ECCPoint(Datasource& ds, const int curveID) :
    ds(ds),
    curveID(curveID) {
    if ( (point = wc_ecc_new_point_h(nullptr)) == nullptr ) {
        throw std::exception();
    }
}

/* Copy constructor */
ECCPoint::ECCPoint(const ECCPoint& other) :
    ds(other.ds),
    curveID(other.curveID),
    locked(other.locked),
    initialized(other.initialized)
{
    if ( (point = wc_ecc_new_point_h(nullptr)) == nullptr ) {
        throw std::exception();
    }

    if ( wc_ecc_copy_point(other.point, point) != 0 ) {
        CF_NORET(wc_ecc_del_point(point));
        throw std::exception();
    }
}

ECCPoint::~ECCPoint() {
    CF_NORET(wc_ecc_del_point(point));
}

ecc_point* ECCPoint::GetPtr() {
    uint8_t* out = nullptr;
    ecc_point* newPoint = nullptr;

    if ( locked == false && initialized == true ) {
        bool exportToDER = false;
        try {
            exportToDER = ds.Get<bool>();
        } catch ( ... ) { }

        if ( exportToDER == true ) {
            const int curveIdx = wc_ecc_get_curve_idx(curveID);
            CF_CHECK_NE(newPoint = wc_ecc_new_point_h(nullptr), nullptr);

            word32 outSz = 0xFFFF;
            try { outSz = ds.Get<word32>() & 0xFFFF; } catch ( ... ) { }

            out = util::malloc(outSz);

            CF_CHECK_EQ(wc_ecc_export_point_der(curveIdx, point, out, &outSz), 0);

            {
                haveAllocFailure = false;
                const bool success = wc_ecc_import_point_der(out, outSz, curveIdx, newPoint) == 0;

                if ( success ) {
                    /* Point imported. Replace old point with new point. */

                    CF_NORET(wc_ecc_del_point(point));
                    point = newPoint;
                    newPoint = nullptr;
                } else {
                    /* Failure */

                    if ( haveAllocFailure == false ) {
                        /* Failure is only acceptable if an allocation failure occured, crash otherwise */
                        CF_ASSERT(0, "Cannot import DER-exported ECC point");
                    }
                }
            }
        }
    }

end:
    util::free(out);
    CF_NORET(wc_ecc_del_point(newPoint));

    return point;
}

void ECCPoint::Lock(void) {
    locked = true;
}

void ECCPoint::SetInitialized(void) {
    initialized = true;
}

std::optional<component::BignumPair> ECCPoint::ToBignumPair(void) {
    std::optional<component::BignumPair> ret = std::nullopt;

    wolfCrypt_bignum::Bignum pub_x(GetPtr()->x, ds);

    /* Pointer is stored in pub_x; lock to prevent UAF */
    Lock();

    wolfCrypt_bignum::Bignum pub_y(GetPtr()->y, ds);

    std::optional<std::string> pub_x_str, pub_y_str;
    CF_CHECK_NE(pub_x_str = pub_x.ToDecString(), std::nullopt);
    CF_CHECK_NE(pub_y_str = pub_y.ToDecString(), std::nullopt);

    ret = { *pub_x_str, *pub_y_str };
end:

    return ret;
}

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic_Generic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    try {
        ECCKey key(ds);

        /* Initialize */
        {
            CF_CHECK_EQ(key.SetCurve(op.curveType), true);
            CF_CHECK_EQ(key.LoadPrivateKey(op.priv), true);
        }

        /* Process/Finalize */
        {
            auto pub = key.MakePub();
            CF_CHECK_NE(pub, std::nullopt);

            ret = pub->ToBignumPair();
        }
    } catch ( ... ) { }

end:

    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECC_ValidatePubkey_Generic(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<int> curveID;

    try {
        ECCKey key(ds);
        {
            const char* name = nullptr;

            CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

            CF_CHECK_NE(name = wc_ecc_get_name(*curveID), nullptr);

            CF_CHECK_EQ(wc_ecc_import_raw(
                        key.GetPtr(),
                        util::DecToHex(op.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);
            haveAllocFailure = false;
            ret = wc_ecc_check_key(key.GetPtr()) == 0;
            if ( *ret == false && haveAllocFailure == true ) {
                ret = std::nullopt;
            }
        }
    } catch ( ... ) { }

end:

    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
}

std::optional<bool> OpECDSA_Verify_Generic(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

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

    try {
        ECCKey key(ds);
        {
            const char* name = nullptr;

            CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

            CF_CHECK_NE(name = wc_ecc_get_name(*curveID), nullptr);

            CF_CHECK_EQ(wc_ecc_import_raw(
                        key.GetPtr(),
                        util::DecToHex(op.signature.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.signature.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);
            CF_CHECK_EQ(wc_ecc_check_key(key.GetPtr()), 0);
        }

        CF_CHECK_EQ(wc_ecc_rs_to_sig(
                    util::DecToHex(op.signature.signature.first.ToTrimmedString()).c_str(),
                    util::DecToHex(op.signature.signature.second.ToTrimmedString()).c_str(),
                    sig, &sigSz), 0);

        if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
            const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
            CF_CHECK_EQ(wc_ecc_verify_hash(sig, sigSz, CT.GetPtr(), CT.GetSize(), &verify, key.GetPtr()), 0);
        } else {
            std::optional<wc_HashType> hashType;
            CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);

            const auto hashSize = wc_HashGetDigestSize(*hashType);
            hash = util::malloc(hashSize);

            CF_CHECK_EQ(wc_Hash(*hashType, op.cleartext.GetPtr(), op.cleartext.GetSize(), hash, hashSize), 0);

            const auto CT = Buffer(hash, hashSize).ECDSA_RandomPad(ds, op.curveType);
            CF_CHECK_EQ(wc_ecc_verify_hash(sig, sigSz, CT.GetPtr(), CT.GetSize(), &verify, key.GetPtr()), 0);
        }

        ret = verify ? true : false;
    } catch ( ... ) { }

end:

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

    uint8_t* sig = nullptr;
    word32 sigSz = ECC_MAX_SIG_SIZE;
    Buffer CT;
    uint8_t* hash = nullptr;
    size_t hashSize = 0;
    uint8_t* nonce_bytes = nullptr;
    wolfCrypt_bignum::Bignum nonce(ds), r(ds), s(ds);

    CF_CHECK_NE(op.priv.ToTrimmedString(), "0");

    {
        try {
            sigSz = ds.Get<uint8_t>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        sig = util::malloc(sigSz);
    }

    try {
        ECCKey key(ds);
        CF_CHECK_EQ(key.SetCurve(op.curveType), true);
        CF_CHECK_EQ(key.LoadPrivateKey(op.priv), true);
        key.GetPtr()->type = ECC_PRIVATEKEY_ONLY;

        if ( op.UseSpecifiedNonce() == true ) {
            CF_CHECK_EQ(nonce.Set(op.nonce.ToString(ds)), true);

            const size_t nonce_bytes_size = mp_unsigned_bin_size(nonce.GetPtr());

            /* Convert nonce to byte array */
            nonce_bytes = util::malloc(nonce_bytes_size);
            CF_CHECK_EQ(mp_to_unsigned_bin(nonce.GetPtr(), nonce_bytes), 0);

            /* Set nonce */
            CF_CHECK_EQ(wc_ecc_sign_set_k(nonce_bytes, nonce_bytes_size, key.GetPtr()), 0);
        }

        auto pub = key.MakePub();
        CF_CHECK_NE(pub, std::nullopt);

        if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
            CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
        } else {
            std::optional<wc_HashType> hashType;
            CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);

            hashSize = wc_HashGetDigestSize(*hashType);
            hash = util::malloc(hashSize);

            CF_CHECK_EQ(wc_Hash(*hashType, op.cleartext.GetPtr(), op.cleartext.GetSize(), hash, hashSize), 0);

            CT = Buffer(hash, hashSize).ECDSA_RandomPad(ds, op.curveType);
        }

        /* Sign */
        CF_CHECK_EQ(wc_ecc_sign_hash(CT.GetPtr(), CT.GetSize(), sig, &sigSz, wolfCrypt_detail::GetRNG(), key.GetPtr()), 0);

        /* Verify */
        {
            int verify;
            haveAllocFailure = false;
            if ( wc_ecc_verify_hash(sig, sigSz, CT.GetPtr(), CT.GetSize(), &verify, key.GetPtr()) == 0 && haveAllocFailure == false ) {
                CF_ASSERT(verify, "Cannot verify generated signature");
            }
        }

        CF_CHECK_EQ(DecodeECC_DSA_Sig(sig, sigSz, r.GetPtr(), s.GetPtr()), 0);
        {
            std::optional<std::string> r_str, s_str;

            if ( op.curveType.Get() == CF_ECC_CURVE("secp256k1") ) {
                wolfCrypt_bignum::Bignum SMax(ds);
                CF_CHECK_EQ(SMax.Set("57896044618658097711785492504343953926418782139537452191302581570759080747168"), true);
                if ( mp_cmp(s.GetPtr(), SMax.GetPtr()) == 1 ) {
                    wolfCrypt_bignum::Bignum SSub(ds);
                    CF_CHECK_EQ(SSub.Set("115792089237316195423570985008687907852837564279074904382605163141518161494337"), true);
                    CF_CHECK_EQ(mp_sub(SSub.GetPtr(), s.GetPtr(), s.GetPtr()), 0);
                }
            } else if ( op.curveType.Get() == CF_ECC_CURVE("secp256r1") ) {
                wolfCrypt_bignum::Bignum SMax(ds);
                CF_CHECK_EQ(SMax.Set("57896044605178124381348723474703786764998477612067880171211129530534256022184"), true);
                if ( mp_cmp(s.GetPtr(), SMax.GetPtr()) == 1 ) {
                    wolfCrypt_bignum::Bignum SSub(ds);
                    CF_CHECK_EQ(SSub.Set("115792089210356248762697446949407573529996955224135760342422259061068512044369"), true);
                    CF_CHECK_EQ(mp_sub(SSub.GetPtr(), s.GetPtr(), s.GetPtr()), 0);
                }
            }

            CF_CHECK_NE(r_str = r.ToDecString(), std::nullopt);
            CF_CHECK_NE(s_str = s.ToDecString(), std::nullopt);

            const auto pub2 = pub->ToBignumPair();
            CF_CHECK_NE(pub2, std::nullopt);

            ret = component::ECDSA_Signature({*r_str, *s_str}, *pub2);
        }
    } catch ( ... ) { }
end:

    util::free(sig);
    util::free(hash);
    util::free(nonce_bytes);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Ciphertext> OpECIES_Encrypt_Generic(operation::ECIES_Encrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
#if !defined(HAVE_ECC_ENCRYPT)
    (void)op;
#else
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);
    uint8_t* out = nullptr;

    CF_CHECK_TRUE(op.cipherType.Is(CF_CIPHER("AES_128_CBC")));
    CF_CHECK_EQ(op.iv, std::nullopt);

    try {
        ECCKey priv(ds), pub(ds);
        word32 outSz = ds.Get<uint32_t>() % 0xFFFFFF;

        /* Initialize private key */
        {
            CF_CHECK_TRUE(priv.SetCurve(op.curveType));
            CF_CHECK_TRUE(priv.LoadPrivateKey(op.priv));
            CF_CHECK_TRUE(priv.SetRNG());
        }

        /* Initialize public key */
        {
            std::optional<int> curveID;
            const char* name = nullptr;

            CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

            CF_CHECK_NE(name = wc_ecc_get_name(*curveID), nullptr);

            CF_CHECK_EQ(wc_ecc_import_raw(
                        pub.GetPtr(),
                        util::DecToHex(op.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);

            CF_CHECK_TRUE(pub.SetRNG());
        }

        out = util::malloc(outSz);

        CF_CHECK_EQ(wc_ecc_encrypt(priv.GetPtr(), pub.GetPtr(), op.cleartext.GetPtr(), op.cleartext.GetSize(), out, &outSz, nullptr), 0);

        ret = component::Ciphertext(Buffer(out, outSz));
    } catch ( ... ) { }

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();
#endif
    return ret;
}

std::optional<component::Cleartext> OpECIES_Decrypt_Generic(operation::ECIES_Decrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;
#if !defined(HAVE_ECC_ENCRYPT)
    (void)op;
#else
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);
    uint8_t* out = nullptr;

    CF_CHECK_TRUE(op.cipherType.Is(CF_CIPHER("AES_128_CBC")));
    CF_CHECK_EQ(op.iv, std::nullopt);

    try {
        ECCKey priv(ds), pub(ds);
        word32 outSz = ds.Get<uint32_t>() % 0xFFFFFF;

        /* Initialize private key */
        {
            CF_CHECK_TRUE(priv.SetCurve(op.curveType));
            CF_CHECK_TRUE(priv.LoadPrivateKey(op.priv));
            CF_CHECK_TRUE(priv.SetRNG());
        }

        /* Initialize public key */
        {
            std::optional<int> curveID;
            const char* name = nullptr;

            CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

            CF_CHECK_NE(name = wc_ecc_get_name(*curveID), nullptr);

            CF_CHECK_EQ(wc_ecc_import_raw(
                        pub.GetPtr(),
                        util::DecToHex(op.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);

            CF_CHECK_TRUE(pub.SetRNG());
        }

        out = util::malloc(outSz);

        CF_CHECK_EQ(wc_ecc_decrypt(priv.GetPtr(), pub.GetPtr(), op.ciphertext.GetPtr(), op.ciphertext.GetSize(), out, &outSz, nullptr), 0);

        ret = component::Cleartext(Buffer(out, outSz));
    } catch ( ... ) { }

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();
#endif
    return ret;
}

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
