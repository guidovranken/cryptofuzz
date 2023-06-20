#include "ecdsa_generic.h"
#include "module_internal.h"
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

        word32 outLen = 0;

        bool compressed = false;
        try { compressed  = ds.Get<bool>();} catch ( ... ) { }

        WC_CHECK_EQ(wc_ecc_export_x963_ex(key, nullptr, &outLen, compressed), LENGTH_ONLY_E);
        x963 = util::malloc(outLen);
        WC_CHECK_EQ(wc_ecc_export_x963_ex(key, x963, &outLen, compressed), 0);;

        /* Get the curve id of the old key */
        int curveID;
        CF_CHECK_NE(curveID = wc_ecc_get_curve_id(key->idx), ECC_CURVE_INVALID);

        const bool valid = wc_ecc_check_key(key) == 0;

        haveAllocFailure = false;
        if ( wc_ecc_import_x963_ex(x963, outLen, newKey, curveID) != 0 ) {
            /* Allowed to fail if either:
             *
             * - Compression is used and the input key is invalid
             * - An allocation failure occured during wc_ecc_import_x963_ex
             */
            CF_ASSERT((compressed && !valid) || haveAllocFailure, "Cannot import X963-exported ECC key");
            goto end;
        }

        if ( compressed ) {
            CF_CHECK_TRUE(valid);
        }

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
    useCustomCurve = false;

    if ( useCustomCurve == false )
#endif
    {
#if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
        std::cout << "Using native curve" << std::endl;
#endif
        std::optional<int> curveID;

        CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(curveType), std::nullopt);
        this->curveID = *curveID;

        WC_CHECK_EQ(wc_ecc_set_curve(GetPtr(), 0, *curveID), 0);
    }
#if !defined(WOLFSSL_SP_MATH)
    else {
 #if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
        std::cout << "Using custom curve" << std::endl;
 #endif
        const ecc_set_type* curveSpec;
        CF_CHECK_NE(curveSpec = GetCustomCurve(curveType.Get()), nullptr);
        WC_CHECK_EQ(wc_ecc_set_custom_curve(GetPtr(), curveSpec), 0);
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

    WC_CHECK_EQ(wc_ecc_import_private_key_ex(priv_bytes->data(), priv_bytes->size(), nullptr, 0, GetPtr(), *curveID), 0);

    ret = true;

end:
    return ret;
}

std::optional<ECCPoint> ECCKey::MakePub(void) {
    std::optional<ECCPoint> ret = std::nullopt;

    ECCPoint pub(ds, *curveID);
    WC_CHECK_EQ(wc_ecc_make_pub(GetPtr(), pub.GetPtr()), 0);
    pub.SetInitialized();

    return pub;

end:
    return ret;
}

bool ECCKey::SetRNG(void) {
    bool ret = false;

    WC_CHECK_EQ(wc_ecc_set_rng(GetPtr(), wolfCrypt_detail::GetRNG()), 0);

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
            bool compressed = false;
            try {
                compressed = ds.Get<bool>();
            } catch ( ... ) { }

            const int curveIdx = wc_ecc_get_curve_idx(curveID);
            CF_CHECK_NE(newPoint = wc_ecc_new_point_h(nullptr), nullptr);

            word32 outSz = 0xFFFF;
            try { outSz = ds.Get<word32>() & 0xFFFF; } catch ( ... ) { }

            out = util::malloc(outSz);

            if ( compressed == false ) {
                WC_CHECK_EQ(wc_ecc_export_point_der(curveIdx, point, out, &outSz), 0);
            } else {
                WC_CHECK_EQ(wc_ecc_export_point_der(curveIdx, point, out, &outSz), 0);
                //WC_CHECK_EQ(wc_ecc_export_point_der_compressed(curveIdx, point, out, &outSz), 0);
            }

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

bool ECCPoint::Set(
        const component::BignumPair& xy,
        const uint64_t curveType,
        const bool pointCheck,
        const bool mp_init_size_ok) {
    bool ret = false;

    bool projective = false;
    try {
        projective = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    wolfCrypt_bignum::Bignum x(ds, mp_init_size_ok);
    wolfCrypt_bignum::Bignum y(ds, mp_init_size_ok);
    wolfCrypt_bignum::Bignum z(ds, mp_init_size_ok);

    if ( projective == false ) {
        CF_CHECK_TRUE(x.Set(xy.first));
        CF_CHECK_TRUE(y.Set(xy.second));
        CF_CHECK_TRUE(z.Set("1"));
    } else {
        const auto proj = util::ToRandomProjective(
                ds,
                xy.first.ToTrimmedString(),
                xy.second.ToTrimmedString(),
                curveType);
        CF_CHECK_TRUE(x.Set(proj[0]));
        CF_CHECK_TRUE(y.Set(proj[1]));
        CF_CHECK_TRUE(z.Set(proj[2]));
    }

    WC_CHECK_EQ(mp_copy(x.GetPtr(), point->x), MP_OKAY);
    WC_CHECK_EQ(mp_copy(y.GetPtr(), point->y), MP_OKAY);
    WC_CHECK_EQ(mp_copy(z.GetPtr(), point->z), MP_OKAY);

    if ( pointCheck ) {
        CF_CHECK_TRUE(CurveCheck());
    }

    SetInitialized();

    ret = true;

end:
    return ret;
}

bool ECCPoint::ToProjective(wolfCrypt_bignum::Bignum& prime) {
    bool ret = false;

    wolfCrypt_bignum::Bignum mu(ds);

    WC_CHECK_EQ(mp_montgomery_calc_normalization(mu.GetPtr(), prime.GetPtr()), MP_OKAY);

    if ( mp_cmp_d(mu.GetPtr(), 1) != MP_EQ ) {
        WC_CHECK_EQ(mp_mulmod(point->x, mu.GetPtr(), prime.GetPtr(), point->x), MP_OKAY);
        WC_CHECK_EQ(mp_mulmod(point->y, mu.GetPtr(), prime.GetPtr(), point->y), MP_OKAY);
        WC_CHECK_EQ(mp_mulmod(point->z, mu.GetPtr(), prime.GetPtr(), point->z), MP_OKAY);
    }

    /* Lock so it isn't attempted to export/import the projective point in GetPtr(),
     * which will lead to incorrect results
     */
    Lock();

    ret = true;

end:
    return ret;
}

bool ECCPoint::CurveCheck(void) const {
    const int curveIdx = wc_ecc_get_curve_idx(curveID);
    return wc_ecc_point_is_on_curve(point, curveIdx) == 0;
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

int ECCPoint::Compare(ECCPoint& other) {
    return wc_ecc_cmp_point(GetPtr(), other.GetPtr());
}

std::optional<bool> ECCPoint::IsNeg(ECCPoint& other, wolfCrypt_bignum::Bignum& prime) {
    std::optional<bool> ret = std::nullopt;

    wolfCrypt_bignum::Bignum neg(ds);
    if ( mp_sub(prime.GetPtr(), other.GetPtr()->y, neg.GetPtr()) == MP_OKAY) {
        ret = static_cast<bool>(mp_cmp(point->y, neg.GetPtr()) == MP_EQ);
    }

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

            WC_CHECK_EQ(wc_ecc_import_raw(
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

    bool ctIsEmpty = false;
    bool randomSigSz = false;
    bool hashNotFound = false;

    {
        try {
            randomSigSz = ds.Get<bool>();
            if ( randomSigSz ) {
                sigSz = ds.Get<uint8_t>();
            }
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        sig = util::malloc(sigSz);
    }

    try {
        ECCKey key(ds);
        {
            const char* name = nullptr;

            CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

            CF_CHECK_NE(name = wc_ecc_get_name(*curveID), nullptr);

            haveAllocFailure = false;
            ret = false;

            WC_CHECK_EQ(wc_ecc_import_raw(
                        key.GetPtr(),
                        util::DecToHex(op.signature.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.signature.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);
            WC_CHECK_EQ(wc_ecc_check_key(key.GetPtr()), 0);
        }

        WC_CHECK_EQ(wc_ecc_rs_to_sig(
                    util::DecToHex(op.signature.signature.first.ToTrimmedString()).c_str(),
                    util::DecToHex(op.signature.signature.second.ToTrimmedString()).c_str(),
                    sig, &sigSz), 0);

        if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
            const auto CT = op.cleartext.ECDSA_RandomPad(ds, op.curveType);
            ctIsEmpty = CT.GetSize() == 0;
            WC_CHECK_EQ(wc_ecc_verify_hash(sig, sigSz, CT.GetPtr(), CT.GetSize(), &verify, key.GetPtr()), 0);
        } else {
            std::optional<wc_HashType> hashType;
            hashNotFound = true;
            CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);
            hashNotFound = false;

            const auto hashSize = wc_HashGetDigestSize(*hashType);
            hash = util::malloc(hashSize);

            WC_CHECK_EQ(wc_Hash(*hashType, op.cleartext.GetPtr(), op.cleartext.GetSize(), hash, hashSize), 0);

            const auto CT = Buffer(hash, hashSize).ECDSA_RandomPad(ds, op.curveType);
            ctIsEmpty = CT.GetSize() == 0;
            WC_CHECK_EQ(wc_ecc_verify_hash(sig, sigSz, CT.GetPtr(), CT.GetSize(), &verify, key.GetPtr()), 0);
        }

        ret = verify ? true : false;
    } catch ( ... ) { }

end:

    util::free(sig);
    util::free(hash);

    wolfCrypt_detail::UnsetGlobalDs();

    if ( ret && *ret == false ) {
        if ( haveAllocFailure ) {
            ret = std::nullopt;
        } else if ( randomSigSz ) {
            ret = std::nullopt;
        } else if ( ctIsEmpty ) {
            /* wolfCrypt ECDSA verification will fail if the input msg is empty */
            ret = std::nullopt;
        } else if ( hashNotFound ) {
            ret = std::nullopt;
        } else if ( op.digestType.Is(CF_DIGEST("NULL")) && op.cleartext.IsZero() ) {
            ret = std::nullopt;
        }
    }

    return ret;
}

std::optional<component::ECCSI_Signature> OpECCSI_Sign(operation::ECCSI_Sign& op) {
#if !defined(WOLFCRYPT_HAVE_ECCSI)
    (void)op;
    return std::nullopt;
#else
    std::optional<component::ECCSI_Signature> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t hashSz = WC_MAX_DIGEST_SIZE;
    static_assert(WC_MAX_DIGEST_SIZE < 256);

    uint8_t* hash = util::malloc(hashSz);

    uint8_t* encoded = nullptr;
    EccsiKey eccsi;
    bool eccsi_initialized = false;

    try {
        int size;
        std::optional<component::BignumPair> pubbn = std::nullopt;

        {
            /* Private to public */
            ECCKey key(ds);
            CF_CHECK_EQ(key.SetCurve(op.curveType), true);
            CF_CHECK_GT(size = key.GetPtr()->dp->size, 0);
            CF_CHECK_EQ(key.LoadPrivateKey(op.priv), true);
            auto pub = key.MakePub();
            CF_CHECK_NE(pub, std::nullopt);
            CF_CHECK_NE(pubbn = pub->ToBignumPair(), std::nullopt);

            /* Encode private and public */
            encoded = util::malloc(size * 3);

            WC_CHECK_EQ(mp_to_unsigned_bin_len(key.GetPtr()->k, encoded, size), 0);
            WC_CHECK_EQ(mp_to_unsigned_bin_len(pub->GetPtr()->x, encoded + size, size), 0);
            WC_CHECK_EQ(mp_to_unsigned_bin_len(pub->GetPtr()->y, encoded + (size * 2), size), 0);
        }

        {
            std::optional<int> curveId;
            CF_CHECK_NE(curveId = toCurveID(op.curveType), std::nullopt);

            WC_CHECK_EQ(wc_InitEccsiKey_ex(&eccsi, size, *curveId, nullptr, -1), 0);
            eccsi_initialized = true;

            WC_CHECK_EQ(wc_ImportEccsiKey(&eccsi, encoded, size * 3), 0);
            {
                uint8_t sig[257]; /* XXX random size */
                word32 sigSz = sizeof(sig);
                ECCPoint pvt(ds, *curveId);
                wolfCrypt_bignum::Bignum ssk(ds);
                std::optional<wc_HashType> hashType;
                CF_CHECK_NE(hashType = toHashType(op.digestType), std::nullopt);
                WC_CHECK_EQ(wc_MakeEccsiPair(
                            &eccsi,
                            &rng,
                            *hashType,
                            op.id.GetPtr(),
                            op.id.GetSize(),
                            ssk.GetPtr(),
                            pvt.GetPtr()), 0);
                WC_CHECK_EQ(wc_HashEccsiId(
                            &eccsi,
                            *hashType,
                            op.id.GetPtr(),
                            op.id.GetSize(),
                            pvt.GetPtr(),
                            hash,
                            &hashSz), 0);
                WC_CHECK_EQ(wc_SetEccsiHash(&eccsi, hash, hashSz), 0);
                WC_CHECK_EQ(wc_SetEccsiPair(&eccsi, ssk.GetPtr(), pvt.GetPtr()), 0);
                WC_CHECK_EQ(wc_SignEccsiHash(
                            &eccsi,
                            &rng,
                            *hashType,
                            op.cleartext.GetPtr(),
                            op.cleartext.GetSize(),
                            sig, &sigSz), 0);
                CF_ASSERT(sigSz == static_cast<size_t>(size) * 4 + 1, "Unexpected signature size");
                {
                    wolfCrypt_bignum::Bignum r(ds), s(ds);
                    std::optional<std::string> r_str, s_str;
                    std::optional<component::BignumPair> pvtbn = std::nullopt;

                    WC_CHECK_EQ(mp_read_unsigned_bin(r.GetPtr(), sig, size), 0);
                    CF_CHECK_NE(r_str = r.ToDecString(), std::nullopt);

                    WC_CHECK_EQ(mp_read_unsigned_bin(s.GetPtr(), sig + size, size), 0);
                    CF_CHECK_NE(s_str = s.ToDecString(), std::nullopt);

                    CF_CHECK_NE(pvtbn = pvt.ToBignumPair(), std::nullopt);

                    ret = component::ECCSI_Signature{
                        component::BignumPair{*r_str, *s_str},
                        *pubbn,
                        *pvtbn};
                }
            }
        }
    } catch ( ... ) { }

end:
    if ( eccsi_initialized ) {
        CF_NORET(wc_FreeEccsiKey(&eccsi));
    }
    util::free(hash);
    util::free(encoded);
    wolfCrypt_detail::UnsetGlobalDs();
    return ret;
#endif
}

std::optional<bool> OpECCSI_Verify(operation::ECCSI_Verify& op) {
#if !defined(WOLFCRYPT_HAVE_ECCSI)
    (void)op;
    return std::nullopt;
#else
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t hashSz = WC_MAX_DIGEST_SIZE;
    static_assert(WC_MAX_DIGEST_SIZE < 256);

    EccsiKey eccsi;

    uint8_t* hash = util::malloc(hashSz);
    std::optional<wc_HashType> hashType;
    std::optional<int> curveId;
    std::vector<uint8_t> pub, sig;
    int verified;
    int size;
    bool eccsi_initialized = false;

    CF_CHECK_NE(curveId = toCurveID(op.curveType), std::nullopt);
    CF_CHECK_NE(hashType = toHashType(op.digestType), std::nullopt);

    haveAllocFailure = false;
    ret = false;

    try {
    {
        ECCKey key(ds);
        CF_CHECK_EQ(key.SetCurve(op.curveType), true);
        CF_CHECK_GT(size = key.GetPtr()->dp->size, 0);
    }

    /* Pub to binary */
    {
        const auto x = op.signature.pub.first.ToBin(size);
        CF_CHECK_NE(x, std::nullopt);
        pub.insert(pub.end(), x->begin(), x->end());

        const auto y = op.signature.pub.second.ToBin(size);
        CF_CHECK_NE(y, std::nullopt);
        pub.insert(pub.end(), y->begin(), y->end());
    }

    /* Sig to binary */
    {
        const auto r = op.signature.signature.first.ToBin(size);
        CF_CHECK_NE(r, std::nullopt);
        sig.insert(sig.end(), r->begin(), r->end());

        const auto s = op.signature.signature.second.ToBin(size);
        CF_CHECK_NE(s, std::nullopt);
        sig.insert(sig.end(), s->begin(), s->end());

        sig.push_back(0x04);

        const auto pvt_x = op.signature.pvt.first.ToBin(size);
        CF_CHECK_NE(pvt_x, std::nullopt);
        sig.insert(sig.end(), pvt_x->begin(), pvt_x->end());

        const auto pvt_y = op.signature.pvt.second.ToBin(size);
        CF_CHECK_NE(pvt_y, std::nullopt);
        sig.insert(sig.end(), pvt_y->begin(), pvt_y->end());
    }

    {
        ECCPoint pvt(ds, *curveId);
        CF_CHECK_TRUE(pvt.Set(
                    op.signature.pvt,
                    op.curveType.Get(),
                    false,
                    false));

        WC_CHECK_EQ(wc_InitEccsiKey_ex(&eccsi, size, *curveId, nullptr, -1), 0);
        eccsi_initialized = true;

        WC_CHECK_EQ(wc_ImportEccsiPublicKey(&eccsi,
                    pub.data(), pub.size(), 0), 0);
        WC_CHECK_EQ(wc_HashEccsiId(
                    &eccsi,
                    *hashType,
                    op.id.GetPtr(&ds), op.id.GetSize(),
                    pvt.GetPtr(),
                    hash,
                    &hashSz), 0);
        WC_CHECK_EQ(wc_SetEccsiHash(&eccsi, hash, hashSz), 0);
        WC_CHECK_EQ(wc_VerifyEccsiHash(
                    &eccsi,
                    *hashType,
                    op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                    sig.data(), sig.size(),
                    &verified), 0);
        ret = verified == 1;
    }
    } catch ( ... ) { }

end:
    if ( eccsi_initialized ) {
        CF_NORET(wc_FreeEccsiKey(&eccsi));
    }
    util::free(hash);
    wolfCrypt_detail::UnsetGlobalDs();
    if ( ret && *ret == false ) {
        if ( haveAllocFailure ) {
            ret = std::nullopt;
        }
    }
    return ret;
#endif
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
    wolfCrypt_bignum::Bignum nonce(ds);

    /* Initialize r, s using mp_init(), not mp_init_size(),
     * as the latter is not compatible with DecodeECC_DSA_Sig().
     *
     * See ZD 15728.
     */
    wolfCrypt_bignum::Bignum r(ds, false), s(ds, false);

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
            WC_CHECK_EQ(wc_ecc_sign_set_k(nonce_bytes, nonce_bytes_size, key.GetPtr()), 0);
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

            WC_CHECK_EQ(wc_Hash(*hashType, op.cleartext.GetPtr(), op.cleartext.GetSize(), hash, hashSize), 0);

            CT = Buffer(hash, hashSize).ECDSA_RandomPad(ds, op.curveType);
        }

        /* Sign */
        WC_CHECK_EQ(wc_ecc_sign_hash(CT.GetPtr(), CT.GetSize(), sig, &sigSz, wolfCrypt_detail::GetRNG(), key.GetPtr()), 0);

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

            WC_CHECK_EQ(wc_ecc_import_raw(
                        pub.GetPtr(),
                        util::DecToHex(op.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);

            CF_CHECK_TRUE(pub.SetRNG());
        }

        out = util::malloc(outSz);

        WC_CHECK_EQ(wc_ecc_encrypt(priv.GetPtr(), pub.GetPtr(), op.cleartext.GetPtr(), op.cleartext.GetSize(), out, &outSz, nullptr), 0);

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

            WC_CHECK_EQ(wc_ecc_import_raw(
                        pub.GetPtr(),
                        util::DecToHex(op.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);

            CF_CHECK_TRUE(pub.SetRNG());
        }

        out = util::malloc(outSz);

        WC_CHECK_EQ(wc_ecc_decrypt(priv.GetPtr(), pub.GetPtr(), op.ciphertext.GetPtr(), op.ciphertext.GetSize(), out, &outSz, nullptr), 0);

        ret = component::Cleartext(Buffer(out, outSz));
    } catch ( ... ) { }

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();
#endif
    return ret;
}

std::optional<component::Secret> OpECDH_Derive(operation::ECDH_Derive& op) {
    std::optional<component::Secret> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    /* try/catch because ECCKey constructor may throw if allocation fails */
    try {
        /* TODO dynamic size */
        uint8_t out[1024];
        word32 outlen = sizeof(out);
        ECCKey priv(ds), pub(ds);

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

            WC_CHECK_EQ(wc_ecc_import_raw(
                        pub.GetPtr(),
                        util::DecToHex(op.pub.first.ToTrimmedString()).c_str(),
                        util::DecToHex(op.pub.second.ToTrimmedString()).c_str(),
                        nullptr,
                        name), 0);
            WC_CHECK_EQ(wc_ecc_check_key(pub.GetPtr()), 0);
        }

        WC_CHECK_EQ(wc_ecc_shared_secret(priv.GetPtr(), pub.GetPtr(), out, &outlen), 0);

        ret = component::Secret(Buffer(out, outlen));
    } catch ( ... ) { }

end:
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECC_Point> OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<int> curveID;
    int curveIdx;
    const ecc_set_type* curve = nullptr;
    bool failed = false;
    bool valid = false;
    std::optional<bool> is_neg = std::nullopt;

    CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

    CF_CHECK_NE(curveIdx = wc_ecc_get_curve_idx(*curveID), ECC_CURVE_INVALID);
    CF_CHECK_NE(curve = wc_ecc_get_curve_params(curveIdx), nullptr);

    /* try/catch because ECCPoint constructor may throw if allocation fails */
    try {
        ECCPoint res(ds, *curveID), a(ds, *curveID), b(ds, *curveID);
        wolfCrypt_bignum::Bignum Af(ds), prime(ds), mu(ds);
        mp_digit mp;

        /* Set points */
        CF_CHECK_TRUE(a.Set(op.a, op.curveType.Get()));
        CF_CHECK_TRUE(b.Set(op.b, op.curveType.Get()));

        valid = a.CurveCheck() && b.CurveCheck();

        /* Retrieve curve parameter */
        CF_CHECK_EQ(Af.Set(util::HexToDec(curve->Af)), true);
        CF_CHECK_EQ(prime.Set(util::HexToDec(curve->prime)), true);

        is_neg = a.IsNeg(b, prime);

        CF_CHECK_TRUE(a.ToProjective(prime));
        CF_CHECK_TRUE(b.ToProjective(prime));

        WC_CHECK_EQ(mp_montgomery_setup(prime.GetPtr(), &mp), MP_OKAY);

#if defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_PUBLIC_ECC_ADD_DBL)
        goto end;
#else
        {
            bool dbl = false;
            bool safe = false;

            if ( a.Compare(b) == MP_EQ ) {
                try { dbl = ds.Get<bool>(); } catch ( ... ) { }
            }

#if !(defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_PUBLIC_ECC_ADD_DBL))
            try { safe = ds.Get<bool>(); } catch ( ... ) { }
#endif

            if ( safe ) {
#if defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_PUBLIC_ECC_ADD_DBL)
                CF_UNREACHABLE();
#else
                int infinity;

                if ( dbl == true ) {
                    failed = true;
                    haveAllocFailure = false;
                    WC_CHECK_EQ(ecc_projective_dbl_point_safe(a.GetPtr(), res.GetPtr(), Af.GetPtr(), prime.GetPtr(), mp), 0);
                    failed = false;
                } else {
                    failed = true;
                    haveAllocFailure = false;
                    WC_CHECK_EQ(ecc_projective_add_point_safe(a.GetPtr(), b.GetPtr(), res.GetPtr(), Af.GetPtr(), prime.GetPtr(), mp, &infinity), 0);
                    failed = false;
                }
#endif
            } else {
                if ( dbl == true ) {
                    failed = true;
                    haveAllocFailure = false;
                    WC_CHECK_EQ(ecc_projective_dbl_point(a.GetPtr(), res.GetPtr(), Af.GetPtr(), prime.GetPtr(), mp), 0);
                    failed = false;
                } else {
                    failed = true;
                    haveAllocFailure = false;
                    WC_CHECK_EQ(ecc_projective_add_point(a.GetPtr(), b.GetPtr(), res.GetPtr(), Af.GetPtr(), prime.GetPtr(), mp), 0);
                    failed = false;

                    /* Do not return result if inputs are negations of the same point */
                    CF_CHECK_NE(is_neg, std::nullopt);
                    CF_CHECK_FALSE(*is_neg);
                }
            }

            /* Lock to prevent exporting the projective point */
            res.Lock();
        }
#endif

        /* To affine */
        WC_CHECK_EQ(ecc_map(res.GetPtr(), prime.GetPtr(), mp), MP_OKAY);

        /* Only return the result if the input points are valid */
        CF_CHECK_TRUE(valid);

        /* Only return the result if the output point is valid */
        CF_CHECK_TRUE(res.CurveCheck());

        ret = res.ToBignumPair();
    } catch ( ... ) { }

end:
    wolfCrypt_detail::UnsetGlobalDs();

    if ( valid ) {
        if ( !haveAllocFailure ) {
            if ( !*is_neg ) {
                CF_ASSERT(!failed, "Point adding failed");
            }
        }
    }

    return ret;
}

std::optional<component::ECC_Point> OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<int> curveID;
    int curveIdx;
    const ecc_set_type* curve = nullptr;

    CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

    CF_CHECK_NE(curveIdx = wc_ecc_get_curve_idx(*curveID), ECC_CURVE_INVALID);
    CF_CHECK_NE(curve = wc_ecc_get_curve_params(curveIdx), nullptr);

    /* try/catch because ECCPoint constructor may throw if allocation fails */
    try {
        ECCPoint res(ds, *curveID), a(ds, *curveID);
        wolfCrypt_bignum::Bignum b(ds), Af(ds), prime(ds);
        bool valid = false;

        /* Set point */
        CF_CHECK_TRUE(a.Set(op.a, op.curveType.Get()));
        valid = a.CurveCheck();

        /* Set multiplier */
        CF_CHECK_EQ(b.Set(op.b.ToString(ds)), true);

        /* Retrieve curve parameters */
        CF_CHECK_EQ(Af.Set(util::HexToDec(curve->Af)), true);
        CF_CHECK_EQ(prime.Set(util::HexToDec(curve->prime)), true);

        /* Multiply */
        WC_CHECK_EQ(wc_ecc_mulmod_ex(b.GetPtr(), a.GetPtr(), res.GetPtr(), Af.GetPtr(), prime.GetPtr(), 1, nullptr), 0);

        /* Only return the result if the input point is valid */
        CF_CHECK_TRUE(valid);

        ret = res.ToBignumPair();
    } catch ( ... ) { }

end:
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECC_Point> OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<int> curveID;
    int curveIdx;
    const ecc_set_type* curve = nullptr;
    bool failed = false;
    bool valid = false;

    CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

    CF_CHECK_NE(curveIdx = wc_ecc_get_curve_idx(*curveID), ECC_CURVE_INVALID);
    CF_CHECK_NE(curve = wc_ecc_get_curve_params(curveIdx), nullptr);

    /* try/catch because ECCPoint constructor may throw if allocation fails */
    try {
        ECCPoint res(ds, *curveID), a(ds, *curveID);
        wolfCrypt_bignum::Bignum Af(ds), prime(ds), mu(ds);
        mp_digit mp;

        /* Set points */
        CF_CHECK_TRUE(a.Set(op.a, op.curveType.Get()));

        valid = a.CurveCheck();

        /* Retrieve curve parameter */
        CF_CHECK_EQ(Af.Set(util::HexToDec(curve->Af)), true);
        CF_CHECK_EQ(prime.Set(util::HexToDec(curve->prime)), true);

        CF_CHECK_TRUE(a.ToProjective(prime));

        WC_CHECK_EQ(mp_montgomery_setup(prime.GetPtr(), &mp), MP_OKAY);

#if defined(WOLFSSL_SP_MATH) && !defined(WOLFSSL_PUBLIC_ECC_ADD_DBL)
        goto end;
#else
        {
            bool safe = false;

#if !(defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_PUBLIC_ECC_ADD_DBL))
            try { safe = ds.Get<bool>(); } catch ( ... ) { }
#endif

            if ( safe ) {
#if defined(WOLFSSL_SP_MATH) && defined(WOLFSSL_PUBLIC_ECC_ADD_DBL)
                CF_UNREACHABLE();
#else
                failed = true;
                haveAllocFailure = false;
                WC_CHECK_EQ(ecc_projective_dbl_point_safe(a.GetPtr(), res.GetPtr(), Af.GetPtr(), prime.GetPtr(), mp), 0);
                failed = false;
#endif
            } else {
                failed = true;
                haveAllocFailure = false;
                WC_CHECK_EQ(ecc_projective_dbl_point(a.GetPtr(), res.GetPtr(), Af.GetPtr(), prime.GetPtr(), mp), 0);
                failed = false;
            }

            /* Lock to prevent exporting the projective point */
            res.Lock();
        }
#endif

        /* To affine */
        WC_CHECK_EQ(ecc_map(res.GetPtr(), prime.GetPtr(), mp), MP_OKAY);

        /* Only return the result if the input points are valid */
        CF_CHECK_TRUE(valid);

        /* Only return the result if the output point is valid */
        CF_CHECK_TRUE(res.CurveCheck());

        ret = res.ToBignumPair();
    } catch ( ... ) { }

end:
    if ( valid ) {
        if ( !haveAllocFailure ) {
            CF_ASSERT(!failed, "Point doubling failed");
        }
    }

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<bool> OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) {
#if 0
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<int> curveID;
    int curveIdx;
    const ecc_set_type* curve = nullptr;

    CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

    CF_CHECK_NE(curveIdx = wc_ecc_get_curve_idx(*curveID), ECC_CURVE_INVALID);
    CF_CHECK_NE(curve = wc_ecc_get_curve_params(curveIdx), nullptr);

    /* try/catch because ECCPoint constructor may throw if allocation fails */
    try {
        ECCPoint res(ds, *curveID), a(ds, *curveID), b(ds, *curveID);
        wolfCrypt_bignum::Bignum Af(ds), prime(ds), mu(ds);
        bool valid = false;

        /* Set points */
        CF_CHECK_TRUE(a.Set(op.a, op.curveType.Get()));
        CF_CHECK_TRUE(b.Set(op.b, op.curveType.Get()));

        valid = a.CurveCheck() && b.CurveCheck();
        (void)valid;

        /* Retrieve curve parameter */
        CF_CHECK_EQ(Af.Set(util::HexToDec(curve->Af)), true);
        CF_CHECK_EQ(prime.Set(util::HexToDec(curve->prime)), true);

        CF_CHECK_TRUE(a.ToProjective(prime));
        CF_CHECK_TRUE(b.ToProjective(prime));

        ret = wc_ecc_cmp_point(a.GetPtr(), b.GetPtr()) == MP_EQ;
    } catch ( ... ) { }

end:
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
#else
    /* ZD 15599 */
    (void)op;
    return std::nullopt;
#endif
}

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
