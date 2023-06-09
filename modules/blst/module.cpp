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
    std::optional<std::array<uint8_t, Size>> ToArray(const component::Bignum& bn, const bool reverse = true) {
        const auto _ret = util::DecToBin(bn.ToTrimmedString(), Size);
        if ( _ret == std::nullopt ) {
            return std::nullopt;
        }

        std::array<uint8_t, Size> ret;
        memcpy(ret.data(), _ret->data(), Size);
        if ( reverse == true ) {
            Reverse<>(ret);
        }

        return ret;
    }
    bool To_blst_fr(const component::Bignum& bn, blst_fr& out) {
        const auto ret = ToArray<32>(bn);

        if ( ret == std::nullopt ) {
            return false;
        }

        CF_NORET(blst_fr_from_uint64(&out, (const uint64_t*)ret->data()));
        return true;
    }
    bool To_blst_fp(const component::Bignum& bn, blst_fp& out) {
        const auto ret = ToArray<48>(bn);

        if ( ret == std::nullopt ) {
            return false;
        }

        CF_NORET(blst_fp_from_uint64(&out, (const uint64_t*)ret->data()));
        return true;
    }
    bool To_blst_fp2(const component::Fp2& bn, blst_fp2& out) {
        return  To_blst_fp(bn.first, out.fp[0]) &&
                To_blst_fp(bn.second, out.fp[1]);
    }
    bool To_blst_fp12(const component::Fp12& bn, blst_fp12& out) {
        return  To_blst_fp(bn.bn1, out.fp6[0].fp2[0].fp[0]) &&
                To_blst_fp(bn.bn2, out.fp6[0].fp2[0].fp[1]) &&
                To_blst_fp(bn.bn3, out.fp6[0].fp2[1].fp[0]) &&
                To_blst_fp(bn.bn4, out.fp6[0].fp2[1].fp[1]) &&
                To_blst_fp(bn.bn5, out.fp6[0].fp2[2].fp[0]) &&
                To_blst_fp(bn.bn6, out.fp6[0].fp2[2].fp[1]) &&

                To_blst_fp(bn.bn7, out.fp6[1].fp2[0].fp[0]) &&
                To_blst_fp(bn.bn8, out.fp6[1].fp2[0].fp[1]) &&
                To_blst_fp(bn.bn9, out.fp6[1].fp2[1].fp[0]) &&
                To_blst_fp(bn.bn10, out.fp6[1].fp2[1].fp[1]) &&
                To_blst_fp(bn.bn11, out.fp6[1].fp2[2].fp[0]) &&
                To_blst_fp(bn.bn12, out.fp6[1].fp2[2].fp[1]);
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
    component::Fp2 To_component_Fp2(const blst_fp2& in) {
        std::array<uint8_t, 48> v1, v2;

        blst_uint64_from_fp((uint64_t*)v1.data(), &in.fp[0]);
        Reverse<>(v1);

        blst_uint64_from_fp((uint64_t*)v2.data(), &in.fp[1]);
        Reverse<>(v2);

        return {
            util::BinToDec(v1.data(), 48),
            util::BinToDec(v2.data(), 48),
        };
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

    component::Fp12 To_component_Fp12(const blst_fp12& fp12) {
        std::array<uint8_t, 48> bn1, bn2, bn3, bn4, bn5, bn6, bn7, bn8, bn9, bn10, bn11, bn12;

        blst_uint64_from_fp((uint64_t*)bn1.data(), &fp12.fp6[0].fp2[0].fp[0]);
        Reverse<>(bn1);

        blst_uint64_from_fp((uint64_t*)bn2.data(), &fp12.fp6[0].fp2[0].fp[1]);
        Reverse<>(bn2);

        blst_uint64_from_fp((uint64_t*)bn3.data(), &fp12.fp6[0].fp2[1].fp[0]);
        Reverse<>(bn3);

        blst_uint64_from_fp((uint64_t*)bn4.data(), &fp12.fp6[0].fp2[1].fp[1]);
        Reverse<>(bn4);

        blst_uint64_from_fp((uint64_t*)bn5.data(), &fp12.fp6[0].fp2[2].fp[0]);
        Reverse<>(bn5);

        blst_uint64_from_fp((uint64_t*)bn6.data(), &fp12.fp6[0].fp2[2].fp[1]);
        Reverse<>(bn6);

        blst_uint64_from_fp((uint64_t*)bn7.data(), &fp12.fp6[1].fp2[0].fp[0]);
        Reverse<>(bn7);

        blst_uint64_from_fp((uint64_t*)bn8.data(), &fp12.fp6[1].fp2[0].fp[1]);
        Reverse<>(bn8);

        blst_uint64_from_fp((uint64_t*)bn9.data(), &fp12.fp6[1].fp2[1].fp[0]);
        Reverse<>(bn9);

        blst_uint64_from_fp((uint64_t*)bn10.data(), &fp12.fp6[1].fp2[1].fp[1]);
        Reverse<>(bn10);

        blst_uint64_from_fp((uint64_t*)bn11.data(), &fp12.fp6[1].fp2[2].fp[0]);
        Reverse<>(bn11);

        blst_uint64_from_fp((uint64_t*)bn12.data(), &fp12.fp6[1].fp2[2].fp[1]);
        Reverse<>(bn12);

        return {
            util::BinToDec(bn1.data(), 48),
            util::BinToDec(bn2.data(), 48),
            util::BinToDec(bn3.data(), 48),
            util::BinToDec(bn4.data(), 48),
            util::BinToDec(bn5.data(), 48),
            util::BinToDec(bn6.data(), 48),
            util::BinToDec(bn7.data(), 48),
            util::BinToDec(bn8.data(), 48),
            util::BinToDec(bn9.data(), 48),
            util::BinToDec(bn10.data(), 48),
            util::BinToDec(bn11.data(), 48),
            util::BinToDec(bn12.data(), 48),
        };
    }

    bool To_blst_scalar(const component::Bignum& bn, blst_scalar& out) {
        const auto ret = ToArray<32>(bn);

        if ( ret == std::nullopt ) {
            return false;
        }

        CF_NORET(blst_scalar_from_uint64(&out, (const uint64_t*)ret->data()));

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
    static bool IsZero(const blst_p2_affine* g2) {
        blst_p2_affine zero;
        memset(&zero, 0, sizeof(zero));
        return memcmp(g2, &zero, sizeof(zero)) == 0;
    }

    static std::optional<blst_p1_affine> Load_G1_Affine(const component::G1& g1) {
        std::optional<blst_p1_affine> ret = std::nullopt;

        blst_p1_affine aff_a;

        CF_CHECK_TRUE(blst_detail::To_blst_fp(g1.first, aff_a.x));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(g1.second, aff_a.y));

        ret = aff_a;
end:
        return ret;
    }

    static std::optional<blst_p1> Load_G1_Projective(
            fuzzing::datasource::Datasource& ds,
            const component::G1& g1) {
        std::optional<blst_p1> ret = std::nullopt;

        blst_p1 a;

        const auto proj = util::ToRandomProjective(
                ds,
                g1.first.ToTrimmedString(),
                g1.second.ToTrimmedString(),
                CF_ECC_CURVE("BLS12_381"));

        CF_CHECK_TRUE(blst_detail::To_blst_fp(proj[0], a.x));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(proj[1], a.y));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(proj[2], a.z));

        ret = a;
end:
        return ret;
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

    /* blst_sk_to_pk_in_g1 does not reduce the private key,
     * so check if it's valid first
     */
    CF_CHECK_TRUE(blst_sk_check(&priv));

    CF_NORET(blst_sk_to_pk_in_g1(&pub, &priv));
    CF_ASSERT(blst_p1_on_curve(&pub) == true, "Generated pubkey not on curve");
    CF_ASSERT(blst_p1_in_g1(&pub) == true, "Generated pubkey not in group");

    CF_NORET(blst_p1_to_affine(&pub_affine, &pub));

    {
        blst_detail::G1 g1(pub_affine, ds);
        ret = g1.To_Component_G1();
    }

end:
    return ret;
}

std::optional<component::G2> blst::OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_scalar priv;
    blst_p2 pub;
    blst_p2_affine pub_affine;

    CF_CHECK_TRUE(blst_detail::To_blst_scalar(op.priv, priv));

    /* blst_sk_to_pk_in_g2 does not reduce the private key,
     * so check if it's valid first
     */
    CF_CHECK_TRUE(blst_sk_check(&priv));

    CF_NORET(blst_sk_to_pk_in_g2(&pub, &priv));
    CF_ASSERT(blst_p2_on_curve(&pub) == true, "Generated pubkey not on curve");
    CF_ASSERT(blst_p2_in_g2(&pub) == true, "Generated pubkey not in group");

    CF_NORET(blst_p2_to_affine(&pub_affine, &pub));

    ret = blst_detail::To_G2(pub_affine);

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

    CF_NORET(blst_hash_to_g1(
            &g1,
            op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
            op.dest.GetPtr(&ds), op.dest.GetSize(),
            op.aug.GetPtr(&ds), op.aug.GetSize()));

    CF_ASSERT(blst_p1_on_curve(&g1) == true, "Generated g1 not on curve");
    CF_ASSERT(blst_p1_in_g1(&g1) == true, "Generated g1 not in group");

    CF_NORET(blst_p1_to_affine(&g1_affine, &g1));

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

    CF_NORET(blst_hash_to_g2(
            &g2,
            op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
            op.dest.GetPtr(&ds), op.dest.GetSize(),
            op.aug.GetPtr(&ds), op.aug.GetSize()));

    CF_ASSERT(blst_p2_on_curve(&g2) == true, "Generated g2 not on curve");
    CF_ASSERT(blst_p2_in_g2(&g2) == true, "Generated g2 not in group");

    CF_NORET(blst_p2_to_affine(&g2_affine, &g2));

    ret = blst_detail::To_G2(g2_affine);

    return ret;
}

std::optional<component::G1> blst::OpBLS_MapToG1(operation::BLS_MapToG1& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p1 g1;
    blst_p1_affine g1_affine;
    blst_fp u, v;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.u, u));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.v, v));

    CF_NORET(blst_map_to_g1(&g1, &u, &v));

    CF_ASSERT(blst_p1_on_curve(&g1) == true, "Generated g1 not on curve");
    CF_ASSERT(blst_p1_in_g1(&g1) == true, "Generated g1 not in group");

    CF_NORET(blst_p1_to_affine(&g1_affine, &g1));

    {
        blst_detail::G1 _g1(g1_affine, ds);
        ret = _g1.To_Component_G1();
    }

end:
    return ret;
}

std::optional<component::G2> blst::OpBLS_MapToG2(operation::BLS_MapToG2& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p2 g2;
    blst_p2_affine g2_affine;
    blst_fp2 u, v;

    CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.u, u));
    CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.v, v));

    CF_NORET(blst_map_to_g2(&g2, &u, &v));

    CF_ASSERT(blst_p2_on_curve(&g2) == true, "Generated g2 not on curve");
    CF_ASSERT(blst_p2_in_g2(&g2) == true, "Generated g2 not in group");

    CF_NORET(blst_p2_to_affine(&g2_affine, &g2));

    ret = blst_detail::To_G2(g2_affine);

end:
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

    CF_NORET(blst_sk_to_pk_in_g1(&pub, &priv));
    CF_ASSERT(blst_p1_on_curve(&pub) == true, "Generated pubkey not on curve");
    CF_ASSERT(blst_p1_in_g1(&pub) == true, "Generated pubkey not in group");
    CF_NORET(blst_p1_to_affine(&pub_affine, &pub));

    if ( op.hashOrPoint == true ) {
        CF_NORET(blst_hash_to_g2(
                &hash,
                op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                op.dest.GetPtr(&ds), op.dest.GetSize(),
                op.aug.GetPtr(&ds), op.aug.GetSize()));
    } else {
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.first.first, hash_affine.x.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.first.second, hash_affine.y.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.second.first, hash_affine.x.fp[1]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(op.point.second.second, hash_affine.y.fp[1]));
        CF_NORET(blst_p2_from_affine(&hash, &hash_affine));
    }
    CF_NORET(blst_sign_pk_in_g1(&signature, &hash, &priv));

    if ( op.hashOrPoint == true ) {
        CF_ASSERT(blst_p2_on_curve(&signature) == true, "Generated signature not on curve");
        CF_ASSERT(blst_p2_in_g2(&signature) == true, "Generated signature not in group");
    } else {
        if ( blst_p2_affine_on_curve(&hash_affine) ) {
            CF_ASSERT(blst_p2_on_curve(&signature) == true, "Generated signature not on curve");
        }

        if ( blst_p2_affine_in_g2(&hash_affine) ) {
            CF_ASSERT(blst_p2_in_g2(&signature) == true, "Generated signature not in group");
        }
    }

    CF_NORET(blst_p2_to_affine(&signature_affine, &signature));

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

namespace blst_detail {
    std::optional<bool> Verify(
            Datasource& ds,
            const component::Cleartext& msg,
            const component::Cleartext& dst,
            const component::Cleartext& aug,
            const component::G1& pub,
            const component::G2& sig,
            const bool hashOrEncode) {
    std::optional<bool> ret = std::nullopt;

    blst_p1_affine pub_affine;
    blst_p2_affine sig_affine;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(pub.first, pub_affine.x));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(pub.second, pub_affine.y));

    if ( !(blst_p1_affine_on_curve(&pub_affine) && blst_p1_affine_in_g1(&pub_affine)) ) {
        return false;
    }

    CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.first.first, sig_affine.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.first.second, sig_affine.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.second.first, sig_affine.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.second.second, sig_affine.y.fp[1]));

    if ( !(blst_p2_affine_on_curve(&sig_affine) && blst_p2_affine_in_g2(&sig_affine)) ) {
        return false;
    }

    ret = blst_core_verify_pk_in_g1(
                &pub_affine, &sig_affine,
                hashOrEncode,
                msg.GetPtr(&ds), msg.GetSize(),
                dst.GetPtr(&ds), dst.GetSize(),
                aug.GetPtr(&ds), aug.GetSize()) == BLST_SUCCESS;

end:
    return ret;
}
}

std::optional<bool> blst::OpBLS_Verify(operation::BLS_Verify& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        //return std::nullopt;
    }
    if ( op.hashOrPoint == false ) {
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

std::optional<bool> blst::OpBLS_BatchVerify(operation::BLS_BatchVerify& op) {
    std::optional<bool> ret = std::nullopt;

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const blst_fp12 one = *blst_fp12_one();
    blst_fp12 f = *blst_fp12_one();

    for (const auto& cur : op.bf.c) {
            blst_p1_affine g1_affine;
            blst_p2_affine g2_affine;

            /* Load G1 */
            CF_CHECK_TRUE(blst_detail::To_blst_fp(cur.g1.first, g1_affine.x));
            CF_CHECK_TRUE(blst_detail::To_blst_fp(cur.g1.second, g1_affine.y));

            CF_CHECK_TRUE(blst_p1_affine_on_curve(&g1_affine) && blst_p1_affine_in_g1(&g1_affine));

            /* Load G2 */
            CF_CHECK_TRUE(blst_detail::To_blst_fp(cur.g2.first.first, g2_affine.x.fp[0]));
            CF_CHECK_TRUE(blst_detail::To_blst_fp(cur.g2.first.second, g2_affine.y.fp[0]));
            CF_CHECK_TRUE(blst_detail::To_blst_fp(cur.g2.second.first, g2_affine.x.fp[1]));
            CF_CHECK_TRUE(blst_detail::To_blst_fp(cur.g2.second.second, g2_affine.y.fp[1]));

            CF_CHECK_TRUE(blst_p2_affine_on_curve(&g2_affine) && blst_p2_affine_in_g2(&g2_affine));

            blst_fp12 tmp;
            CF_NORET(blst_miller_loop(&tmp, &g2_affine, &g1_affine));
            CF_NORET(blst_fp12_mul(&f, &f, &tmp));
    }

    CF_NORET(blst_final_exp(&f, &f));

    ret = blst_fp12_is_equal(&f, &one) == 1;

end:
    return ret;
}

std::optional<bool> blst::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool useAffine = true;

    try {
        useAffine = ds.Get<bool>();
    } catch ( fuzzing::datasource::Base::OutOfData ) { }

    if ( useAffine ) {
        std::optional<blst_p1_affine> aff_g1;
        CF_CHECK_NE(aff_g1 = blst_detail::Load_G1_Affine(op.g1), std::nullopt);
        return
            !blst_p1_affine_is_inf(&*aff_g1) &&
            blst_p1_affine_on_curve(&*aff_g1) &&
            blst_p1_affine_in_g1(&*aff_g1);
    } else {
        std::optional<blst_p1> g1;
        CF_CHECK_NE(g1 = blst_detail::Load_G1_Projective(ds, op.g1), std::nullopt);
        return
            !blst_p1_is_inf(&*g1) &&
            blst_p1_on_curve(&*g1) &&
            blst_p1_in_g1(&*g1);
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

    CF_CHECK_FALSE(blst_detail::IsZero(&g2_affine));

    if ( useAffine ) {
        return blst_p2_affine_on_curve(&g2_affine) && blst_p2_affine_in_g2(&g2_affine);
    } else {
        CF_NORET(blst_p2_from_affine(&g2, &g2_affine));
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

    CF_NORET(blst_keygen(&priv, op.ikm.GetPtr(&ds), op.ikm.GetSize(), op.info.GetPtr(&ds), op.info.GetSize()));
    CF_ASSERT(blst_sk_check(&priv) == true, "blst_keygen generated invalid private key");

    CF_NORET(blst_sk_to_pk_in_g1(&pub, &priv));
    CF_NORET(blst_p1_to_affine(&pub_affine, &pub));

    {
        std::array<uint8_t, 32> priv_bytes;
        CF_NORET(blst_uint64_from_scalar((uint64_t*)priv_bytes.data(), &priv));

        blst_detail::Reverse<>(priv_bytes);
        blst_detail::G1 g1(pub_affine, ds);

        {
            const auto priv = util::BinToDec(priv_bytes.data(), 32);
            const auto pub = g1.To_Component_G1();

            CF_ASSERT(blst_p1_affine_on_curve(&pub_affine) == true, "Generated public key not on curve");
            CF_ASSERT(blst_p1_affine_in_g1(&pub_affine), "Generated public key not in group");

            ret = {priv, pub};
        }
    }

    return ret;
}

std::optional<component::G1> blst::OpBLS_Aggregate_G1(operation::BLS_Aggregate_G1& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::G1> ret = std::nullopt;

    blst_p1 res;
    blst_p1_affine res_affine;

    bool first = true;
    for (const auto& sig : op.points.points) {
        uint8_t serialized[96];
        blst_p1_affine a;
        blst_p1 a_;

        CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.first, a.x));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.second, a.y));

        CF_NORET(blst_p1_from_affine(&a_, &a));

        CF_NORET(blst_p1_serialize(serialized, &a_));

        CF_CHECK_EQ(
                blst_aggregate_in_g1(
                    &res,
                    first == true ? nullptr : &res,
                    serialized), BLST_SUCCESS);

        first = false;
    }

    if ( first == false ) {
        CF_NORET(blst_p1_to_affine(&res_affine, &res));
        CF_ASSERT(blst_p1_affine_on_curve(&res_affine) && blst_p1_affine_in_g1(&res_affine), "Aggregate created invalid point");
        blst_detail::G1 _g1(res_affine, ds);
        ret = _g1.To_Component_G1();
    }

end:
    return ret;
}

std::optional<component::G2> blst::OpBLS_Aggregate_G2(operation::BLS_Aggregate_G2& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::G2> ret = std::nullopt;

    blst_p2 res;
    blst_p2_affine res_affine;

    bool first = true;
    for (const auto& sig : op.points.points) {
        uint8_t serialized[192];
        blst_p2_affine a;
        blst_p2 a_;

        CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.first.first, a.x.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.first.second, a.y.fp[0]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.second.first, a.x.fp[1]));
        CF_CHECK_TRUE(blst_detail::To_blst_fp(sig.second.second, a.y.fp[1]));

        CF_NORET(blst_p2_from_affine(&a_, &a));

        CF_NORET(blst_p2_serialize(serialized, &a_));

        CF_CHECK_EQ(
                blst_aggregate_in_g2(
                    &res,
                    first == true ? nullptr : &res,
                    serialized), BLST_SUCCESS);

        first = false;
    }

    if ( first == false ) {
        CF_NORET(blst_p2_to_affine(&res_affine, &res));
        CF_ASSERT(blst_p2_affine_on_curve(&res_affine) && blst_p2_affine_in_g2(&res_affine), "Aggregate created invalid point");
        ret = blst_detail::To_G2(res_affine);
    }

end:
    return ret;
}

std::optional<component::Fp12> blst::OpBLS_Pairing(operation::BLS_Pairing& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Fp12> ret = std::nullopt;

    blst_p1_affine g1_affine;
    blst_p2_affine g2_affine;
    blst_fp12 out;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g1.first, g1_affine.x));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g1.second, g1_affine.y));

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.first.first, g2_affine.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.first.second, g2_affine.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.second.first, g2_affine.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.second.second, g2_affine.y.fp[1]));

    CF_NORET(blst_miller_loop(&out, &g2_affine, &g1_affine));
    CF_NORET(blst_final_exp(&out, &out));

    ret = blst_detail::To_component_Fp12(out);

end:
    return ret;
}

std::optional<component::Fp12> blst::OpBLS_MillerLoop(operation::BLS_MillerLoop& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Fp12> ret = std::nullopt;

    blst_p1_affine g1_affine;
    blst_p2_affine g2_affine;
    blst_fp12 out;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g1.first, g1_affine.x));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g1.second, g1_affine.y));

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.first.first, g2_affine.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.first.second, g2_affine.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.second.first, g2_affine.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.g2.second.second, g2_affine.y.fp[1]));

    CF_NORET(blst_miller_loop(&out, &g2_affine, &g1_affine));

    ret = blst_detail::To_component_Fp12(out);

end:
    return ret;
}

std::optional<component::Fp12> blst::OpBLS_FinalExp(operation::BLS_FinalExp& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::optional<component::Fp12> ret = std::nullopt;

    blst_fp12 out;

    CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.fp12, out));

    CF_NORET(blst_final_exp(&out, &out));

    ret = blst_detail::To_component_Fp12(out);

end:
    return ret;
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
        static const blst_fr zero = {0};

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
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));

                    size_t shiftCount;
                    uint8_t which = 0;
                    try {
                        which = ds.Get<uint8_t>() % 3;
                    } catch ( fuzzing::datasource::Base::OutOfData ) {
                    }
                    if ( which == 1 ) {
                        if ( op.bn1.ToTrimmedString() != "3" ) {
                            which = 0;
                        }
                    } else if ( which == 2 ) {
                        shiftCount = blst_detail::isMultipleOf2(op.bn1.ToTrimmedString());
                        if ( shiftCount == 0 ) {
                            which = 0;
                        }
                    }

                    switch ( which ) {
                        case    0:
                            CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                            PREPARE_RESULT();
                            CF_NORET(blst_fr_mul(RESULT_PTR(), &A, PARAM_B()));
                            break;
                        case    1:
                            PREPARE_RESULT();
                            CF_NORET(blst_fr_mul_by_3(RESULT_PTR(), &A));
                            break;
                        case    2:
                            PREPARE_RESULT();
                            blst_fr_lshift(RESULT_PTR(), &A, shiftCount);
                            ret = blst_detail::To_component_bignum(RESULT());
                            break;
                    }

                    ret = blst_detail::To_component_bignum(RESULT());
                }
                break;
            case    CF_CALCOP("Sqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                PREPARE_RESULT();
                blst_fr_sqr(RESULT_PTR(), &A);
                ret = blst_detail::To_component_bignum(RESULT());
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));

                    bool which = false;
                    try {
                        which = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Base::OutOfData ) {
                    }

                    if ( which ) {
                        PREPARE_RESULT();
                        CF_NORET(blst_fr_eucl_inverse(RESULT_PTR(), &A));
                    } else {
                        PREPARE_RESULT();
                        CF_NORET(blst_fr_inverse(RESULT_PTR(), &A));
                    }

                    ret = blst_detail::To_component_bignum(RESULT());
                }
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
            case    CF_CALCOP("IsEq(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                ret = memcmp(&A, &B, sizeof(A)) == 0 ? std::string("1") : std::string("0");
                break;
            case    CF_CALCOP("IsZero(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                ret = memcmp(&A, &zero, sizeof(A)) == 0 ? std::string("1") : std::string("0");
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
        static const blst_fp zero = {0};

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
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));

                    size_t shiftCount;
                    uint8_t which = 0;
                    try {
                        which = ds.Get<uint8_t>() % 4;
                    } catch ( fuzzing::datasource::Base::OutOfData ) {
                    }

                    if ( which == 1 ) {
                        if ( op.bn1.ToTrimmedString() != "3" ) {
                            which = 0;
                        }
                    } else if ( which == 2 ) {
                        if ( op.bn1.ToTrimmedString() != "8" ) {
                            which = 0;
                        }
                    } else if ( which == 3 ) {
                        shiftCount = blst_detail::isMultipleOf2(op.bn1.ToTrimmedString());
                        if ( shiftCount == 0 ) {
                            which = 0;
                        }
                    }

                    switch ( which ) {
                        case    0:
                            CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                            PREPARE_RESULT();
                            CF_NORET(blst_fp_mul(RESULT_PTR(), &A, PARAM_B()));
                            break;
                        case    1:
                            PREPARE_RESULT();
                            CF_NORET(blst_fp_mul_by_3(RESULT_PTR(), &A));
                            break;
                        case    2:
                            PREPARE_RESULT();
                            CF_NORET(blst_fp_mul_by_8(RESULT_PTR(), &A));
                            break;
                        case    3:
                            size_t shiftCount;
                            CF_CHECK_NE(shiftCount = blst_detail::isMultipleOf2(op.bn1.ToTrimmedString()), 0);

                            PREPARE_RESULT();
                            blst_fp_lshift(RESULT_PTR(), &A, shiftCount);
                            ret = blst_detail::To_component_bignum(RESULT());
                            break;
                    }

                    ret = blst_detail::To_component_bignum(RESULT());
                }
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
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));

                    bool which = false;
                    try {
                        which = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Base::OutOfData ) {
                    }

                    if ( which ) {
                        PREPARE_RESULT();
                        CF_NORET(blst_fp_eucl_inverse(RESULT_PTR(), &A));
                    } else {
                        PREPARE_RESULT();
                        CF_NORET(blst_fp_inverse(RESULT_PTR(), &A));
                    }

                    ret = blst_detail::To_component_bignum(RESULT());
                }
                break;
            case    CF_CALCOP("Sqrt(A)"):
                {
                    blst_fp result2;
                    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));

                    if ( blst_fp_sqrt(&result, &A) == true ) {
                        CF_NORET(blst_fp_sqr(&result, &result));
                        ret = blst_detail::To_component_bignum(result);
                    } else {
                        CF_NORET(blst_fp_cneg(&A, &A, 1));
                        CF_ASSERT(blst_fp_sqrt(&A, &A) == true, "Square root must exist");

                        ret = std::string("0");
                    }
                }
                break;
            case    CF_CALCOP("IsSquare(A)"):
                {
                    blst_fp tmp;

                    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                    const bool is_square = blst_fp_is_square(&A);

                    if ( !is_square ) {
                        CF_NORET(blst_fp_cneg(&tmp, &A, 1));
                        CF_ASSERT(blst_fp_is_square(&tmp) == true, "Must be square");
                    } else {
                        CF_ASSERT(blst_fp_sqrt(&tmp, &A) == true, "Square root must exist");
                    }

                    CF_ASSERT(
                            is_square ==
                            blst_fp_sqrt(&result, &A), "");
                    ret = is_square ? std::string("1") : std::string("0");
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
            case    CF_CALCOP("IsEq(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                ret = memcmp(&A, &B, sizeof(A)) == 0 ? std::string("1") : std::string("0");
                break;
            case    CF_CALCOP("IsZero(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                ret = memcmp(&A, &zero, sizeof(A)) == 0 ? std::string("1") : std::string("0");
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

namespace blst_detail {
    #define PREPARE_RESULT() {resultIdx = GetMod3(ds);}
    #define RESULT_PTR() (resultIdx == 0 ? &result : (resultIdx == 1 ? &A : &B))
    #define RESULT() (resultIdx == 0 ? result : (resultIdx == 1 ? A : B))
    #define PARAM_B() (UseParamTwice(ds, &A, &B) ? &A : &B)

    std::optional<component::Fp2> OpBignumCalc_Fp2_prime(operation::BignumCalc_Fp2& op) {
        std::optional<component::Fp2> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        blst_fp2 result, A, B;
        uint8_t resultIdx;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn1, B));
                PREPARE_RESULT();
                blst_fp2_add(RESULT_PTR(), &A, PARAM_B());
                ret = blst_detail::To_component_Fp2(RESULT());
                break;
            case    CF_CALCOP("Sub(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn1, B));
                PREPARE_RESULT();
                blst_fp2_sub(RESULT_PTR(), &A, PARAM_B());
                ret = blst_detail::To_component_Fp2(RESULT());
                break;
            case    CF_CALCOP("Mul(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn1, B));
                PREPARE_RESULT();
                CF_NORET(blst_fp2_mul(RESULT_PTR(), &A, PARAM_B()));

                ret = blst_detail::To_component_Fp2(RESULT());
                break;
            case    CF_CALCOP("LShift1(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                PREPARE_RESULT();
                blst_fp2_lshift(RESULT_PTR(), &A, 1);
                ret = blst_detail::To_component_Fp2(RESULT());
                break;
            case    CF_CALCOP("Sqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                PREPARE_RESULT();
                blst_fp2_sqr(RESULT_PTR(), &A);
                ret = blst_detail::To_component_Fp2(RESULT());
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));

                    bool which = false;
                    try {
                        which = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Base::OutOfData ) {
                    }

                    if ( which ) {
                        PREPARE_RESULT();
                        CF_NORET(blst_fp2_eucl_inverse(RESULT_PTR(), &A));
                    } else {
                        PREPARE_RESULT();
                        CF_NORET(blst_fp2_inverse(RESULT_PTR(), &A));
                    }

                    ret = blst_detail::To_component_Fp2(RESULT());
                }
                break;
            case    CF_CALCOP("Sqrt(A)"):
                {
                    blst_fp result2;
                    CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));

                    if ( blst_fp2_sqrt(&result, &A) == true ) {
                        CF_NORET(blst_fp2_sqr(&result, &result));
                        ret = blst_detail::To_component_Fp2(result);
                    } else {
                        ret = { std::string("0"), std::string("0") };
                    }
                }
                break;
            case    CF_CALCOP("IsSquare(A)"):
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                    const bool is_square = blst_fp2_is_square(&A);
                    CF_ASSERT(
                            is_square ==
                            blst_fp2_sqrt(&result, &A), "");
                }
                break;
            case    CF_CALCOP("Not(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                PREPARE_RESULT();
                blst_fp2_cneg(RESULT_PTR(), &A, true);
                ret = blst_detail::To_component_Fp2(RESULT());
                break;
            case    CF_CALCOP("Set(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp2(op.bn0, A));
                ret = blst_detail::To_component_Fp2(A);
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

std::optional<component::Fp2> blst::OpBignumCalc_Fp2(operation::BignumCalc_Fp2& op) {
    return blst_detail::OpBignumCalc_Fp2_prime(op);
}

namespace blst_detail {
    #define PREPARE_RESULT() {resultIdx = GetMod3(ds);}
    #define RESULT_PTR() (resultIdx == 0 ? &result : (resultIdx == 1 ? &A : &B))
    #define RESULT() (resultIdx == 0 ? result : (resultIdx == 1 ? A : B))
    #define PARAM_B() (UseParamTwice(ds, &A, &B) ? &A : &B)

    std::optional<component::Fp12> OpBignumCalc_Fp12_prime(operation::BignumCalc_Fp12& op) {
        std::optional<component::Fp12> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        blst_fp12 result, A, B;
        uint8_t resultIdx;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Mul(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.bn1, B));
                PREPARE_RESULT();
                CF_NORET(blst_fp12_mul(RESULT_PTR(), &A, PARAM_B()));

                ret = blst_detail::To_component_Fp12(RESULT());
                break;
            case    CF_CALCOP("Conjugate(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.bn0, A));
                CF_NORET(blst_fp12_conjugate(&A));
                ret = blst_detail::To_component_Fp12(A);
                break;
            case    CF_CALCOP("Sqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.bn0, A));
                PREPARE_RESULT();
                CF_NORET(blst_fp12_sqr(RESULT_PTR(), &A));
                ret = blst_detail::To_component_Fp12(RESULT());
                break;
            case    CF_CALCOP("CyclotomicSqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.bn1, B));
                CF_NORET(blst_fp12_cyclotomic_sqr(&A, &B));
                ret = blst_detail::To_component_Fp12(A);
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp12(op.bn0, A));

                PREPARE_RESULT();
                CF_NORET(blst_fp12_inverse(RESULT_PTR(), &A));

                ret = blst_detail::To_component_Fp12(RESULT());
                break;
            case    CF_CALCOP("One()"):
                ret = blst_detail::To_component_Fp12(*(blst_fp12_one()));
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

std::optional<component::Fp12> blst::OpBignumCalc_Fp12(operation::BignumCalc_Fp12& op) {
    return blst_detail::OpBignumCalc_Fp12_prime(op);
}

std::optional<component::G1> blst::OpBLS_Decompress_G1(operation::BLS_Decompress_G1& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p1_affine point;
    std::optional<std::array<uint8_t, 48>> compressed = std::nullopt;

    CF_CHECK_NE(compressed = blst_detail::ToArray<48>(op.compressed, false), std::nullopt);

    if ( blst_p1_uncompress(&point, compressed->data()) == BLST_SUCCESS ) {
        blst_detail::G1 g1(point, ds);
        ret = g1.To_Component_G1();
    } else {
        ret = component::G1{"0", "0"};
    }

end:
    return ret;
}

std::optional<component::Bignum> blst::OpBLS_Compress_G1(operation::BLS_Compress_G1& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    std::array<uint8_t, 48> out;
    blst_p1_affine point;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.uncompressed.first, point.x));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.uncompressed.second, point.y));
    //CF_CHECK_FALSE(blst_detail::IsZero(&point));

    CF_CHECK_TRUE(blst_p1_affine_on_curve(&point));

    CF_NORET(blst_p1_affine_compress(out.data(), &point));
    ret = util::BinToDec(out.data(), 48);

end:
    return ret;
}

std::optional<component::G2> blst::OpBLS_Decompress_G2(operation::BLS_Decompress_G2& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p2_affine point;
    std::optional<std::array<uint8_t, 48>> compressed_x = std::nullopt;
    std::optional<std::array<uint8_t, 48>> compressed_y = std::nullopt;
    std::array<uint8_t, 96> compressed;

    CF_CHECK_NE(compressed_x = blst_detail::ToArray<48>(op.compressed.first, false), std::nullopt);
    CF_CHECK_NE(compressed_y = blst_detail::ToArray<48>(op.compressed.second, false), std::nullopt);

    memcpy(compressed.data(), compressed_x->data(), 48);
    memcpy(compressed.data() + 48, compressed_y->data(), 48);

    if ( blst_p2_uncompress(&point, compressed.data()) == BLST_SUCCESS ) {
        ret = blst_detail::To_G2(point);
    } else {
        ret = component::G2{"0", "0", "0", "0"};
    }

end:
    return ret;
}

std::optional<component::G1> blst::OpBLS_Compress_G2(operation::BLS_Compress_G2& op) {
    std::optional<component::G1> ret = std::nullopt;

    std::array<uint8_t, 96> out;
    blst_p2_affine point;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.uncompressed.first.first, point.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.uncompressed.first.second, point.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.uncompressed.second.first, point.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.uncompressed.second.second, point.y.fp[1]));

    CF_CHECK_TRUE(blst_p2_affine_on_curve(&point));

    CF_NORET(blst_p2_affine_compress(out.data(), &point));
    ret = { util::BinToDec(out.data(), 48), util::BinToDec(out.data() + 48, 48) };

end:
    return ret;
}

std::optional<component::G1> blst::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<blst_p1_affine> aff_tmp;
    blst_p1_affine aff_a, aff_b, aff_result;

    std::optional<blst_p1> tmp;
    blst_p1 a, b, result;

    bool eq;
    uint8_t mode = 0;
    bool doAffine = true;

    CF_CHECK_NE(aff_tmp = blst_detail::Load_G1_Affine(op.a), std::nullopt);
    aff_a = *aff_tmp;

    CF_CHECK_NE(aff_tmp = blst_detail::Load_G1_Affine(op.b), std::nullopt);
    aff_b = *aff_tmp;

    CF_CHECK_NE(tmp = blst_detail::Load_G1_Projective(ds, op.a), std::nullopt);
    a = *tmp;

    CF_CHECK_NE(tmp = blst_detail::Load_G1_Projective(ds, op.b), std::nullopt);
    b = *tmp;

    eq = blst_p1_is_equal(&a, &b);

    try {
        mode = ds.Get<uint8_t>() % 3;
    } catch ( fuzzing::datasource::Base::OutOfData ) {
    }

    /* Modes:
     *
     * 0 = pure add
     * 1 = pure double
     * 2 = mixed add and double
     */

    if ( mode == 0 && eq ) {
        mode = 1;
    } else if ( mode == 1 && !eq ) {
        mode = 0;
    }

    try {
        doAffine = ds.Get<bool>();
    } catch ( fuzzing::datasource::Base::OutOfData ) {
    }

    switch ( mode ) {
        case    0:
            if ( doAffine == true ) {
                bool doMulti = false;
                try {
                    doMulti = ds.Get<bool>();
                } catch ( fuzzing::datasource::Base::OutOfData ) {
                }

                if ( doMulti == false ) {
                    CF_NORET(blst_p1_add_affine(&result, &a, &aff_b));
                } else {
                    const blst_p1_affine *const points[2] = {&aff_a, &aff_b};
                    CF_NORET(blst_p1s_add(&result, points, 2));
                }
            } else {
                CF_NORET(blst_p1_add(&result, &a, &b));
            }
            break;
        case    1:
            CF_NORET(blst_p1_double(&result, &a));
            break;
        case    2:
            if ( doAffine == true ) {
                CF_NORET(blst_p1_add_or_double_affine(&result, &a, &aff_b));
            } else {
                CF_NORET(blst_p1_add_or_double(&result, &a, &b));
            }
            break;
        default:
            CF_UNREACHABLE();
    }

    CF_CHECK_TRUE(
            !blst_p1_affine_is_inf(&aff_a) &&
            blst_p1_affine_on_curve(&aff_a) &&
            blst_p1_affine_in_g1(&aff_a));
    CF_CHECK_TRUE(
            !blst_p1_affine_is_inf(&aff_b) &&
            blst_p1_affine_on_curve(&aff_b) &&
            blst_p1_affine_in_g1(&aff_b));

    CF_NORET(blst_p1_to_affine(&aff_result, &result));

    {
        blst_detail::G1 g1(aff_result, ds);
        ret = g1.To_Component_G1();
    }

end:
    return ret;
}

std::optional<component::G1> blst::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p1_affine aff_result;
    std::optional<blst_p1> tmp;
    blst_p1 a, result;
    std::optional<std::vector<uint8_t>> b;

    CF_CHECK_NE(tmp = blst_detail::Load_G1_Projective(ds, op.a), std::nullopt);
    a = *tmp;

    CF_CHECK_NE(b = util::DecToBin(op.b.ToTrimmedString()), std::nullopt);

    {
        std::vector<uint8_t> b_reversed = util::AddLeadingZeroes(ds, *b);
        CF_NORET(std::reverse(b_reversed.begin(), b_reversed.end()));

        Buffer B(b_reversed);

        CF_NORET(blst_p1_mult(&result, &a, B.GetPtr(&ds), B.GetSize() * 8));
    }

    CF_NORET(blst_p1_to_affine(&aff_result, &result));

    CF_CHECK_TRUE(
            !blst_p1_is_inf(&a) &&
            blst_p1_on_curve(&a) &&
            blst_p1_in_g1(&a));

    {
        blst_detail::G1 g1(aff_result, ds);
        ret = g1.To_Component_G1();
    }

end:
    return ret;
}

std::optional<bool> blst::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<blst_p1_affine> aff_tmp;
    blst_p1_affine aff_a, aff_b;

    std::optional<blst_p1> tmp;
    blst_p1 a, b;

    bool doAffine = false;

    CF_CHECK_NE(aff_tmp = blst_detail::Load_G1_Affine(op.a), std::nullopt);
    aff_a = *aff_tmp;

    CF_CHECK_NE(aff_tmp = blst_detail::Load_G1_Affine(op.b), std::nullopt);
    aff_b = *aff_tmp;

    CF_CHECK_NE(tmp = blst_detail::Load_G1_Projective(ds, op.a), std::nullopt);
    a = *tmp;

    CF_CHECK_NE(tmp = blst_detail::Load_G1_Projective(ds, op.b), std::nullopt);
    b = *tmp;

    try {
        doAffine = ds.Get<bool>();
    } catch ( fuzzing::datasource::Base::OutOfData ) {
    }

    if ( doAffine == true ) {
        ret = blst_p1_affine_is_equal(&aff_a, &aff_b);
    } else {
        ret = blst_p1_is_equal(&a, &b);
    }

end:
    return ret;
}

std::optional<component::G1> blst::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p1_affine aff_result;
    std::optional<blst_p1> tmp;
    blst_p1 a;

    CF_CHECK_NE(tmp = blst_detail::Load_G1_Projective(ds, op.a), std::nullopt);
    a = *tmp;

    CF_NORET(blst_p1_cneg(&a, true));

    CF_NORET(blst_p1_to_affine(&aff_result, &a));

    {
        blst_detail::G1 g1(aff_result, ds);
        ret = g1.To_Component_G1();
    }

end:
    return ret;
}

std::optional<component::G2> blst::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p2_affine a, b, result_;
    blst_p2 a_, b_, result;
    bool doDouble = false;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.first, a.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.second, a.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.first, a.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.second, a.y.fp[1]));

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.first.first, b.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.first.second, b.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.second.first, b.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.second.second, b.y.fp[1]));

    CF_NORET(blst_p2_from_affine(&a_, &a));
    CF_NORET(blst_p2_from_affine(&b_, &b));

    if ( blst_p2_is_equal(&a_, &b_) ) {
        try {
            doDouble = ds.Get<bool>();
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }
    }

    if ( doDouble == false ) {
        CF_NORET(blst_p2_add_or_double_affine(&result, &a_, &b));
    } else {
        CF_NORET(blst_p2_double(&result, &a_));
    }


    CF_NORET(blst_p2_to_affine(&result_, &result));

    ret = blst_detail::To_G2(result_);

end:
    return ret;
}

std::optional<component::G2> blst::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p2_affine a, result_;
    blst_p2 a_, result;
    std::optional<std::vector<uint8_t>> b;
    bool doDouble = false;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.first, a.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.second, a.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.first, a.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.second, a.y.fp[1]));
    CF_CHECK_NE(b = util::DecToBin(op.b.ToTrimmedString()), std::nullopt);

    if ( !(blst_p2_affine_on_curve(&a) && blst_p2_affine_in_g2(&a)) ) {
        return ret;
    }

    CF_NORET(blst_p2_from_affine(&a_, &a));

    if ( op.b.ToTrimmedString() == "2" ) {
        try {
            doDouble = ds.Get<bool>();
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }
    }

    if ( doDouble == false ) {
        std::vector<uint8_t> b_reversed = util::AddLeadingZeroes(ds, *b);
        CF_NORET(std::reverse(b_reversed.begin(), b_reversed.end()));

        Buffer B(b_reversed);

        CF_NORET(blst_p2_mult(&result, &a_, B.GetPtr(&ds), B.GetSize() * 8));
    } else {
        CF_NORET(blst_p2_double(&result, &a_));
    }

    CF_NORET(blst_p2_to_affine(&result_, &result));

    ret = blst_detail::To_G2(result_);

end:
    return ret;
}

std::optional<bool> blst::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    std::optional<bool> ret = std::nullopt;

    blst_p2_affine a, b;
    blst_p2 a_, b_;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.first, a.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.second, a.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.first, a.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.second, a.y.fp[1]));

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.first.first, b.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.first.second, b.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.second.first, b.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.b.second.second, b.y.fp[1]));

    CF_NORET(blst_p2_from_affine(&a_, &a));
    CF_NORET(blst_p2_from_affine(&b_, &b));

    ret = blst_p2_is_equal(&a_, &b_);

end:
    return ret;
}

std::optional<component::G2> blst::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    blst_p2_affine a;
    blst_p2 a_;

    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.first, a.x.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.first.second, a.y.fp[0]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.first, a.x.fp[1]));
    CF_CHECK_TRUE(blst_detail::To_blst_fp(op.a.second.second, a.y.fp[1]));

    CF_NORET(blst_p2_from_affine(&a_, &a));

    CF_NORET(blst_p2_cneg(&a_, true));

    CF_NORET(blst_p2_to_affine(&a, &a_));

    ret = blst_detail::To_G2(a);

end:
    return ret;
}

std::optional<component::G1> blst::OpBLS_G1_MultiExp(operation::BLS_G1_MultiExp& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const size_t num = op.points_scalars.points_scalars.size();
    /* blst_p1s_mult_pippenger crashes with num == 0
     * blst_p1s_mult_pippenger OOB read with num == 1
     */
    if ( num < 2 ) return std::nullopt;

    blst_p1_affine* points = (blst_p1_affine*)util::malloc(num * sizeof(blst_p1_affine));
    const blst_p1_affine* points_ptrs[2] = {points, nullptr};
    blst_scalar* scalars = (blst_scalar*)util::malloc(num * sizeof(blst_scalar));
    const uint8_t* scalars_ptrs[2] = {(uint8_t*)scalars, nullptr};

    uint8_t* scratch = util::malloc(blst_p1s_mult_pippenger_scratch_sizeof(num));

    bool points_are_valid = true;

    for (size_t i = 0; i < num; i++) {
        const auto& cur = op.points_scalars.points_scalars[i];

        std::optional<blst_p1_affine> point;
        CF_CHECK_NE(point = blst_detail::Load_G1_Affine(cur.first), std::nullopt);
        points[i] = *point;

        points_are_valid &=
            !blst_p1_affine_is_inf(&*point) &&
            blst_p1_affine_on_curve(&*point) &&
            blst_p1_affine_in_g1(&*point);

        CF_CHECK_TRUE(blst_detail::To_blst_scalar(cur.second, scalars[i]));
    }

    {
        blst_p1 res;
        CF_NORET(blst_p1s_mult_pippenger(
                    &res,
                    points_ptrs, num,
                    scalars_ptrs, sizeof(blst_scalar) * 8,
                    (limb_t*)scratch));

        CF_CHECK_TRUE(points_are_valid);

        blst_p1_affine res_affine;
        CF_NORET(blst_p1_to_affine(&res_affine, &res));
        blst_detail::G1 g1(res_affine, ds);
        ret = g1.To_Component_G1();
    }

end:
    util::free(points);
    util::free(scalars);
    util::free(scratch);

    return ret;
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
                    CF_NORET(blst_p1_affine_compress(out, &point));
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
                    CF_NORET(blst_p1_affine_serialize(out, &point));
                    if ( blst_p1_affine_on_curve(&point) ) {
                        blst_p1_affine point2;
                        CF_ASSERT(blst_p1_deserialize(&point2, out) == BLST_SUCCESS, "Cannot deserialize serialized point");

                        uint8_t out2[96];
                        CF_NORET(blst_p1_affine_serialize(out2, &point2));
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
                    CF_NORET(blst_p2_affine_compress(out, &point));
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
                    CF_NORET(blst_p2_affine_serialize(out, &point));
                    if ( blst_p2_affine_on_curve(&point) ) {
                        blst_p2_affine point2;
                        CF_ASSERT(blst_p2_deserialize(&point2, out) == BLST_SUCCESS, "Cannot deserialize serialized point");

                        uint8_t out2[192];
                        CF_NORET(blst_p2_affine_serialize(out2, &point2));
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
                    CF_NORET(blst_miller_loop_lines(&out, Qlines, &point));
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
                    CF_NORET(blst_precompute_lines(Qlines, &point));
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

                    CF_NORET(blst_miller_loop(&out, &p2, &p1));
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
