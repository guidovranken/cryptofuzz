#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/multiprecision/cpp_int.hpp>

extern "C" {
#include <blst.h>
}

namespace cryptofuzz {
namespace module {

blst::blst(void) :
    Module("blst") {
}

namespace blst_detail {
    template <size_t Size>
    void Reverse(std::array<uint8_t, Size>& v) {
        std::reverse(v.begin(), v.end());
    }

    template <size_t Size>
    std::optional<std::array<uint8_t, Size>> ToArray(const component::Bignum& bn) {
        const auto _ret = util::DecToBin(bn.ToTrimmedString(), Size);
        if ( _ret == std::nullopt ) {
            return std::nullopt;
        }

        std::array<uint8_t, Size> ret;
        memcpy(ret.data(), _ret->data(), Size);
        Reverse<>(ret);

        return ret;
    }
    bool To_blst_fr(const component::Bignum& bn, blst_fr& out) {
        const auto ret = ToArray<32>(bn);

        if ( ret == std::nullopt ) {
            return false;
        }

        /* noret */ blst_fr_from_uint64(&out, (const uint64_t*)ret->data());
        return true;
    }
    bool To_blst_fp(const component::Bignum& bn, blst_fp& out) {
        const auto ret = ToArray<48>(bn);

        if ( ret == std::nullopt ) {
            return false;
        }

        /* noret */ blst_fp_from_uint64(&out, (const uint64_t*)ret->data());
        return true;
    }
    component::Bignum To_component_bignum(const blst_fr& in) {
        std::array<uint8_t, 32> v;

        blst_uint64_from_fr((uint64_t*)v.data(), &in);

        Reverse<>(v);
        return util::BinToDec(v.data(), 32);
    }
    component::Bignum To_component_bignum(const blst_fp& in) {
        std::array<uint8_t, 48> v;

        blst_uint64_from_fp((uint64_t*)v.data(), &in);

        Reverse<>(v);
        return util::BinToDec(v.data(), 48);
    }
    boost::multiprecision::cpp_int To_cpp_int(const component::Bignum& in) {
        return boost::multiprecision::cpp_int(in.ToTrimmedString());
    }

    class G1 {
        private:
            fuzzing::datasource::Datasource& ds;
            blst_p1_affine g1;
        public:
            G1(const blst_p1_affine& g1, fuzzing::datasource::Datasource& ds) :
                ds(ds) {
                memcpy(&this->g1, &g1, sizeof(g1));
            }
            const blst_p1_affine* Get(void) {
                return &g1;
            }
            component::G1 To_Component_G1(void) {
                std::array<uint8_t, 48> x, y;

                const blst_p1_affine* ptr = Get();

                blst_uint64_from_fp((uint64_t*)x.data(), &ptr->x);
                blst_uint64_from_fp((uint64_t*)y.data(), &ptr->y);

                Reverse<>(x);
                Reverse<>(y);

                return {util::BinToDec(x.data(), 48), util::BinToDec(y.data(), 48)};
            }
    };
    component::G2 To_G2(const blst_p2_affine& g2) {
        std::array<uint8_t, 48> x1, y1, x2, y2;

        blst_uint64_from_fp((uint64_t*)x1.data(), &g2.x.fp[0]);
        blst_uint64_from_fp((uint64_t*)y1.data(), &g2.y.fp[0]);
        blst_uint64_from_fp((uint64_t*)x2.data(), &g2.x.fp[1]);
        blst_uint64_from_fp((uint64_t*)y2.data(), &g2.y.fp[1]);

        Reverse<>(x1);
        Reverse<>(y1);
        Reverse<>(x2);
        Reverse<>(y2);

        return {
            util::BinToDec(x1.data(), 48),
            util::BinToDec(y1.data(), 48),
            util::BinToDec(x2.data(), 48),
            util::BinToDec(y2.data(), 48)
        };
    }
    bool To_blst_scalar(const component::Bignum& bn, blst_scalar& out) {
        const auto ret = ToArray<32>(bn);

        if ( ret == std::nullopt ) {
            return false;
        }

        /* noret */ blst_scalar_from_uint64(&out, (const uint64_t*)ret->data());

        return true;
    }
    bool IsLessThan(const blst_fp& A, const blst_fp& B) {
        std::array<uint8_t, 48> A_words, B_words;

        uint64_t* A_ptr = (uint64_t*)A_words.data();
        uint64_t* B_ptr = (uint64_t*)B_words.data();

        blst_uint64_from_fp(A_ptr, &A);
        blst_uint64_from_fp(B_ptr, &B);

        for (int i = 5; i >= 0; i--) {
            if ( A_ptr[i] == B_ptr[i] ) {
                continue;
            }
            return A_ptr[i] < B_ptr[i];
        }

        return false;
    }

    static size_t isMultipleOf2(const std::string s) {
        auto i = boost::multiprecision::cpp_int(s);
        if ( i == 0 || i == 1 ) {
            return 0;
        }
        size_t num = 0;
        while ( i ) {
            if ( i != 1 && i & 1 ) {
                return 0;
            }
            i >>= 1;
            num++;
        }

        return num - 1;
    }
}

std::optional<component::BLS_PublicKey> blst::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::BLS_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_scalar priv;
    blst_p1 pub;
    blst_p1_affine pub_affine;

    CF_CHECK_TRUE(blst_detail::To_blst_scalar(op.priv, priv));

    /* noret */ blst_sk_to_pk_in_g1(&pub, &priv);
    CF_ASSERT(blst_p1_on_curve(&pub) == true, "Generated pubkey not on curve");

    /* noret */ blst_p1_to_affine(&pub_affine, &pub);

    {
        blst_detail::G1 g1(pub_affine, ds);
        ret = g1.To_Component_G1();
    }

end:
    return ret;
}

std::optional<component::G1> blst::OpBLS_HashToG1(operation::BLS_HashToG1& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p1 g1;
    blst_p1_affine g1_affine;

    /* noret */ blst_hash_to_g1(
            &g1,
            op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
            op.dest.GetPtr(&ds), op.dest.GetSize(),
            op.aug.GetPtr(&ds), op.aug.GetSize());

    CF_ASSERT(blst_p1_on_curve(&g1) == true, "Generated g1 not on curve");

    /* noret */ blst_p1_to_affine(&g1_affine, &g1);

    {
        blst_detail::G1 _g1(g1_affine, ds);
        ret = _g1.To_Component_G1();
    }

    return ret;
}

std::optional<component::G2> blst::OpBLS_HashToG2(operation::BLS_HashToG2& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p2 g2;
    blst_p2_affine g2_affine;

    /* noret */ blst_hash_to_g2(
            &g2,
            op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
            op.dest.GetPtr(&ds), op.dest.GetSize(),
            op.aug.GetPtr(&ds), op.aug.GetSize());

    CF_ASSERT(blst_p2_on_curve(&g2) == true, "Generated g2 not on curve");

    /* noret */ blst_p2_to_affine(&g2_affine, &g2);

    ret = blst_detail::To_G2(g2_affine);

    return ret;
}

std::optional<component::BLS_Signature> blst::OpBLS_Sign(operation::BLS_Sign& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::BLS_Signature> ret;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_scalar priv;
    blst_p1 pub;
    blst_p1_affine pub_affine;
    blst_p2_affine hash_affine;
    blst_p2 hash;
    blst_p2 signature;
    blst_p2_affine signature_affine;

    CF_CHECK_TRUE(blst_detail::To_blst_scalar(op.priv, priv));
    CF_CHECK_TRUE(blst_sk_check(&priv));

    /* noret */ blst_sk_to_pk_in_g1(&pub, &priv);
    CF_ASSERT(blst_p1_on_curve(&pub) == true, "Generated pubkey not on curve");
    /* noret */ blst_p1_to_affine(&pub_affine, &pub);

    if ( op.hashOrPoint == true ) {
        /* noret */ blst_hash_to_g2(
                &hash,
                op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                op.dest.GetPtr(&ds), op.dest.GetSize(),
                op.aug.GetPtr(&ds), op.aug.GetSize());
    } else {
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.first.first, hash_affine.x.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.first.second, hash_affine.y.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.second.first, hash_affine.x.fp[1]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.second.second, hash_affine.y.fp[1]));
        /* noret */ blst_p2_from_affine(&hash, &hash_affine);
    }
    /* noret */ blst_sign_pk_in_g1(&signature, &hash, &priv);

    if ( op.hashOrPoint == true ) {
        CF_ASSERT(blst_p2_on_curve(&signature) == true, "Generated signature not on curve");
    } else {
        if ( blst_p2_affine_on_curve(&hash_affine) ) {
            CF_ASSERT(blst_p2_on_curve(&signature) == true, "Generated signature not on curve");
        }
    }

    /* noret */ blst_p2_to_affine(&signature_affine, &signature);

    {
        blst_detail::G1 g1(pub_affine, ds);
        ret = {blst_detail::To_G2(signature_affine), g1.To_Component_G1()};
    }

    if ( op.hashOrPoint == true ) {
        if ( blst_core_verify_pk_in_g1(
                    &pub_affine, &signature_affine,
                    true,
                    op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                    op.dest.GetPtr(&ds), op.dest.GetSize(),
                    op.aug.GetPtr(&ds), op.aug.GetSize()) != BLST_SUCCESS ) {
            abort();
        }
    }

end:
    return ret;
}

std::optional<bool> blst::OpBLS_Verify(operation::BLS_Verify& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }
    if ( op.hashOrPoint == true ) {
        return std::nullopt;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<bool> ret = std::nullopt;

    blst_p1_affine pub;
    blst_p2_affine sig;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.pub.first, pub.x));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.pub.second, pub.y));

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.signature.first.first, sig.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.signature.first.second, sig.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.signature.second.first, sig.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.signature.second.second, sig.y.fp[1]));

    ret = blst_core_verify_pk_in_g1(
                &pub, &sig,
                true,
                op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                op.dest.GetPtr(&ds), op.dest.GetSize(),
                nullptr, 0) == BLST_SUCCESS;

end:
    return ret;
}

std::optional<bool> blst::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useAffine = true;

    try {
        useAffine = ds.Get<bool>();
    } catch ( fuzzing::datasource::Base::OutOfData ) { }

    blst_p1 g1;
    blst_p1_affine g1_affine;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g1.first, g1_affine.x));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g1.second, g1_affine.y));

    if ( useAffine ) {
        return blst_p1_affine_on_curve(&g1_affine) && blst_p1_affine_in_g1(&g1_affine);
    } else {
        /* noret */ blst_p1_from_affine(&g1, &g1_affine);
        return blst_p1_on_curve(&g1) && blst_p1_in_g1(&g1);
    }

end:
    return false;
}

std::optional<bool> blst::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useAffine = true;

    try {
        useAffine = ds.Get<bool>();
    } catch ( fuzzing::datasource::Base::OutOfData ) { }

    blst_p2 g2;
    blst_p2_affine g2_affine;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.first.first, g2_affine.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.first.second, g2_affine.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.second.first, g2_affine.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.second.second, g2_affine.y.fp[1]));

    if ( useAffine ) {
        return blst_p2_affine_on_curve(&g2_affine) && blst_p2_affine_in_g2(&g2_affine);
    } else {
        /* noret */ blst_p2_from_affine(&g2, &g2_affine);
        return blst_p2_on_curve(&g2) && blst_p2_in_g2(&g2);
    }

end:
    return false;
}

std::optional<component::BLS_KeyPair> blst::OpBLS_GenerateKeyPair(operation::BLS_GenerateKeyPair& op) {
    std::optional<component::BLS_KeyPair> ret = std::nullopt;
    if ( op.ikm.GetSize() < 32 ) {
        return std::nullopt;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_scalar priv;
    blst_p1 pub;
    blst_p1_affine pub_affine;

    /* noret */ blst_keygen(&priv, op.ikm.GetPtr(), op.ikm.GetSize(), op.info.GetPtr(), op.info.GetSize());
    CF_ASSERT(blst_sk_check(&priv) == true, "blst_keygen generated invalid private key");

    /* noret */ blst_sk_to_pk_in_g1(&pub, &priv);
    /* noret */ blst_p1_to_affine(&pub_affine, &pub);

    {
        std::array<uint8_t, 32> priv_bytes;
        /* noret */ blst_uint64_from_scalar((uint64_t*)priv_bytes.data(), &priv);

        blst_detail::Reverse<>(priv_bytes);
        blst_detail::G1 g1(pub_affine, ds);

        {
            const auto priv = util::BinToDec(priv_bytes.data(), 32);
            const auto pub = g1.To_Component_G1();

            CF_ASSERT(blst_p1_affine_on_curve(&pub_affine) == true, "Generated public key not on curve");

            ret = {priv, pub};
        }
    }

    return ret;
}

std::optional<bool> blst::OpBLS_Pairing(operation::BLS_Pairing& op) {
    std::optional<bool> ret = std::nullopt;

    blst_pairing* ctx = (blst_pairing*)util::malloc(blst_pairing_sizeof());

    blst_p1_affine pub;
    blst_p2_affine sig;

    /* noret */ blst_pairing_init(ctx, true, op.dest.GetPtr(), op.dest.GetSize());
    ///* noret */ blst_pairing_init(ctx, false, op.dest.GetPtr(), op.dest.GetSize());

    for (const auto& c : op.components.c) {
        CF_CHECK_TRUE(blst_detail::To_blst_fp(c.pub.first, pub.x));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(c.pub.second, pub.y));

        CF_CHECK_TRUE(blst_detail::To_blst_fp(c.sig.first.first, sig.x.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(c.sig.first.second, sig.y.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(c.sig.second.first, sig.x.fp[1]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(c.sig.second.second, sig.y.fp[1]));

        CF_CHECK_EQ(blst_pairing_aggregate_pk_in_g1(ctx,
                    &pub,
                    &sig,
                    c.msg.GetPtr(), c.msg.GetSize(),
                    c.aug.GetPtr(), c.aug.GetSize()), BLST_SUCCESS);
    }

    /* noret */ blst_pairing_commit(ctx);

    ret = blst_pairing_finalverify(ctx, nullptr);

end:
    util::free(ctx);

    return false;
}

namespace blst_detail {
    template <class T>
    bool UseParamTwice(fuzzing::datasource::Datasource& ds, const T* A, const T* B) {
        if ( memcmp(A, B, sizeof(T)) != 0 ) {
            return false;
        }

        try {
            return ds.Get<bool>();
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        return false;
    }

    uint8_t GetMod3(fuzzing::datasource::Datasource& ds) {
        try {
            return ds.Get<uint8_t>() % 3;
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        return 0;
    }

    #define PREPARE_RESULT() {resultIdx = GetMod3(ds);}
    #define RESULT_PTR() (resultIdx == 0 ? &result : (resultIdx == 1 ? &A : &B))
    #define RESULT() (resultIdx == 0 ? result : (resultIdx == 1 ? A : B))
    #define PARAM_B() (UseParamTwice(ds, &A, &B) ? &A : &B)

    std::optional<component::Bignum> OpBignumCalc_order(operation::BignumCalc& op) {
        std::optional<component::Bignum> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        blst_fr result, A, B;
        uint8_t resultIdx;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                PREPARE_RESULT();
                blst_fr_add(RESULT_PTR(), &A, PARAM_B());
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Sub(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                PREPARE_RESULT();
                blst_fr_sub(RESULT_PTR(), &A, PARAM_B());
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Mul(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));

                try {
                    switch ( ds.Get<uint8_t>() % 3 ) {
                    case    0:
                        CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                        PREPARE_RESULT();
                        /* noret */ blst_fr_mul(RESULT_PTR(), &A, PARAM_B());
                        break;
                    case    1:
                        if ( op.bn1.ToTrimmedString() != "3" ) {
                            goto end;
                        }
                        PREPARE_RESULT();
                        /* noret */ blst_fr_mul_by_3(RESULT_PTR(), &A);
                        break;
                    case    2:
                        {
                            size_t shiftCount;
                            CF_CHECK_NE(shiftCount = blst_detail::isMultipleOf2(op.bn1.ToTrimmedString()), 0);

                            PREPARE_RESULT();
                            blst_fr_lshift(RESULT_PTR(), &A, shiftCount);
                            ret = blst_detail::To_component_bignum(RESULT());
                        }
                        break;
                    }
                } catch ( fuzzing::datasource::Base::OutOfData ) {
                    goto end;
                }

                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Sqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                PREPARE_RESULT();
                blst_fr_sqr(RESULT_PTR(), &A);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                PREPARE_RESULT();
                blst_fr_eucl_inverse(RESULT_PTR(), &A);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("LShift1(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                PREPARE_RESULT();
                blst_fr_lshift(RESULT_PTR(), &A, 1);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("RShift(A,B)"):
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                    const auto B_cpp_int = blst_detail::To_cpp_int(op.bn1);
                    size_t count = static_cast<size_t>(B_cpp_int);
                    CF_CHECK_EQ(count, B_cpp_int);
                    CF_CHECK_GT(count, 0);
                    CF_CHECK_LT(count, 1024000);

                    PREPARE_RESULT();
                    blst_fr_rshift(RESULT_PTR(), &A, count);

                    {
                        CF_CHECK_EQ(count, 1);
                        const auto A_cpp_int = blst_detail::To_cpp_int(op.bn0);
                        CF_CHECK_LT(A_cpp_int, boost::multiprecision::cpp_int("52435875175126190479447740508185965837690552500527637822603658699938581184513"));
                        CF_CHECK_EQ(A_cpp_int % 2, 1);
                        ret = blst_detail::To_component_bignum(RESULT());
                    }
                }
                break;
            case    CF_CALCOP("Not(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                PREPARE_RESULT();
                blst_fr_cneg(RESULT_PTR(), &A, true);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Set(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                ret = blst_detail::To_component_bignum(A);
                break;
        }

end:
        return ret;
    }

    std::optional<component::Bignum> OpBignumCalc_prime(operation::BignumCalc& op) {
        std::optional<component::Bignum> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        blst_fp result, A, B;
        uint8_t resultIdx;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                PREPARE_RESULT();
                blst_fp_add(RESULT_PTR(), &A, PARAM_B());
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Sub(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                PREPARE_RESULT();
                blst_fp_sub(RESULT_PTR(), &A, PARAM_B());
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Mul(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));

                try {
                    switch ( ds.Get<uint8_t>() % 4 ) {
                        case    0:
                            CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                            PREPARE_RESULT();
                            /* noret */ blst_fp_mul(RESULT_PTR(), &A, PARAM_B());
                            break;
                        case    1:
                            if ( op.bn1.ToTrimmedString() != "3" ) {
                                goto end;
                            }

                            PREPARE_RESULT();
                            /* noret */ blst_fp_mul_by_3(RESULT_PTR(), &A);
                            break;
                        case    2:
                            if ( op.bn1.ToTrimmedString() != "8" ) {
                                goto end;
                            }

                            PREPARE_RESULT();
                            /* noret */ blst_fp_mul_by_8(RESULT_PTR(), &A);
                            break;
                        case    3:
                            {
                                size_t shiftCount;
                                CF_CHECK_NE(shiftCount = blst_detail::isMultipleOf2(op.bn1.ToTrimmedString()), 0);

                                PREPARE_RESULT();
                                blst_fp_lshift(RESULT_PTR(), &A, shiftCount);
                                ret = blst_detail::To_component_bignum(RESULT());
                            }
                            break;
                    }
                } catch ( fuzzing::datasource::Base::OutOfData ) {
                    goto end;
                }

                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("LShift1(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                PREPARE_RESULT();
                blst_fp_lshift(RESULT_PTR(), &A, 1);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Sqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                PREPARE_RESULT();
                blst_fp_sqr(RESULT_PTR(), &A);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));

                try {
                    if ( ds.Get<bool>() ) {
                        PREPARE_RESULT();
                        /* noret */ blst_fp_eucl_inverse(RESULT_PTR(), &A);
                    } else {
                        PREPARE_RESULT();
                        /* noret */ blst_fp_inverse(RESULT_PTR(), &A);
                    }
                } catch ( fuzzing::datasource::Base::OutOfData ) {
                    goto end;
                }

                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Sqrt(A)"):
                {
                    blst_fp result2;
                    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));

                    CF_CHECK_EQ(blst_fp_sqrt(&result, &A), true);
                    blst_fp_sqr(&result, &result);

                    ret = blst_detail::To_component_bignum(result);
                }
                break;
            case    CF_CALCOP("Not(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                PREPARE_RESULT();
                blst_fp_cneg(RESULT_PTR(), &A, true);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("Set(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                ret = blst_detail::To_component_bignum(A);
                break;
        }

end:
        return ret;
    }

    #undef PREPARE_RESULT
    #undef RESULT_PTR
    #undef RESULT
    #undef PARAM_B
}

std::optional<component::Bignum> blst::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    /* TODO optimize this */
    if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        return blst_detail::OpBignumCalc_order(op);
    } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        return blst_detail::OpBignumCalc_prime(op);
    } else {
        return std::nullopt;
    }
}

std::optional<Buffer> blst::OpMisc(operation::Misc& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        switch ( op.operation.Get() ) {
            case    0:
                {
                    const auto data = ds.GetData(0, 48, 48);
                    blst_p1_affine point;
                    CF_CHECK_EQ(blst_p1_uncompress(&point, data.data()), BLST_SUCCESS);
                    uint8_t out[48];
                    /* noret */ blst_p1_affine_compress(out, &point);
                    if ( blst_p1_affine_on_curve(&point) ) {
                        CF_ASSERT(memcmp(data.data(), out, data.size()) == 0, "Serialization asymmetry");
                    }
                }
                break;
            case    1:
                {
                    const auto data = ds.GetData(0, 96, 96);
                    blst_p1_affine point;
                    CF_CHECK_EQ(blst_p1_deserialize(&point, data.data()), BLST_SUCCESS);
                    uint8_t out[96];
                    /* noret */ blst_p1_affine_serialize(out, &point);
                    if ( blst_p1_affine_on_curve(&point) ) {
                        blst_p1_affine point2;
                        CF_ASSERT(blst_p1_deserialize(&point2, out) == BLST_SUCCESS, "Cannot deserialize serialized point");

                        uint8_t out2[96];
                        /* noret */ blst_p1_affine_serialize(out2, &point2);
                        CF_ASSERT(memcmp(out, out2, sizeof(out)) == 0, "Serialization asymmetry");
                        //CF_ASSERT(memcmp(data.data(), out, data.size()) == 0, "Serialization asymmetry");
                    }
                }
                break;
            case    2:
                {
                    const auto data = ds.GetData(0, 96, 96);
                    blst_p2_affine point;
                    CF_CHECK_EQ(blst_p2_uncompress(&point, data.data()), BLST_SUCCESS);
                    uint8_t out[96];
                    /* noret */ blst_p2_affine_compress(out, &point);
                    if ( blst_p2_affine_on_curve(&point) ) {
                        CF_ASSERT(memcmp(data.data(), out, data.size()) == 0, "Serialization asymmetry");
                    }
                }
                break;
            case    3:
                {
                    const auto data = ds.GetData(0, 192, 192);
                    blst_p2_affine point;
                    CF_CHECK_EQ(blst_p2_deserialize(&point, data.data()), BLST_SUCCESS);
                    uint8_t out[192];
                    /* noret */ blst_p2_affine_serialize(out, &point);
                    if ( blst_p2_affine_on_curve(&point) ) {
                        blst_p2_affine point2;
                        CF_ASSERT(blst_p2_deserialize(&point2, out) == BLST_SUCCESS, "Cannot deserialize serialized point");

                        uint8_t out2[192];
                        /* noret */ blst_p2_affine_serialize(out2, &point2);
                        CF_ASSERT(memcmp(out, out2, sizeof(out)) == 0, "Serialization asymmetry");
                        //CF_ASSERT(memcmp(data.data(), out, data.size()) == 0, "Serialization asymmetry");
                    }
                }
                break;
            case    4:
                {
                    blst_p1_affine point;
                    {
                        const auto data = ds.GetData(0, 96, 96);
                        CF_CHECK_EQ(blst_p1_deserialize(&point, data.data()), BLST_SUCCESS);
                    }

                    blst_fp6 Qlines[68];
                    {
                        const auto data = ds.GetData(0, sizeof(Qlines), sizeof(Qlines));
                        memcpy(Qlines, data.data(), sizeof(Qlines));
                    }

                    blst_fp12 out;
                    /* noret */ blst_miller_loop_lines(&out, Qlines, &point);
                }
                break;
            case    5:
                {
                    blst_p2_affine point;
                    {
                        const auto data = ds.GetData(0, 192, 192);
                        CF_CHECK_EQ(blst_p2_deserialize(&point, data.data()), BLST_SUCCESS);
                    }

                    blst_fp6 Qlines[68];
                    /* noret */ blst_precompute_lines(Qlines, &point);
                }
                break;
            case    6:
                {
                    blst_fp12 out;
                    blst_p1_affine p1;
                    blst_p2_affine p2;

                    {
                        const auto data = ds.GetData(0, 96, 96);
                        CF_CHECK_EQ(blst_p1_deserialize(&p1, data.data()), BLST_SUCCESS);
                    }

                    {
                        const auto data = ds.GetData(0, 192, 192);
                        CF_CHECK_EQ(blst_p2_deserialize(&p2, data.data()), BLST_SUCCESS);
                    }

                    /* noret */ blst_miller_loop(&out, &p2, &p1);
                }
                break;
        }
    } catch ( fuzzing::datasource::Base::OutOfData ) { }

end:
    return std::nullopt;
}

bool blst::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
