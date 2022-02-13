#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <limits>

#if defined(LIBFF_HAVE_BLS12_381)
  #include <libff/algebra/curves/bls12_381/bls12_381_pp.hpp>
  #include <libff/algebra/curves/edwards/edwards_pp.hpp>
#else
  #include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#endif

#if 0
#include <libff/algebra/curves/mnt/mnt4/mnt4_pp.hpp>
#include <libff/algebra/curves/mnt/mnt6/mnt6_pp.hpp>
#endif

namespace cryptofuzz {
namespace module {

#if defined(LIBFF_HAVE_BLS12_381)
using G1Type = libff::bls12_381_G1;
using G2Type = libff::bls12_381_G2;
using FrType = libff::bls12_381_Fr;
using FqType = libff::bls12_381_Fq;
using Fq2Type = libff::bls12_381_Fq2;
using Fq6Type = libff::bls12_381_Fq6;
using Fq12Type = libff::bls12_381_Fq12;
constexpr size_t FrMaxSize = 77;
constexpr size_t FqMaxSize = 115;
#else
using G1Type = libff::alt_bn128_G1;
using G2Type = libff::alt_bn128_G2;
using FrType = libff::alt_bn128_Fr;
using FqType = libff::alt_bn128_Fq;
using Fq2Type = libff::alt_bn128_Fq2;
using Fq6Type = libff::alt_bn128_Fq6;
using Fq12Type = libff::alt_bn128_Fq12;
constexpr size_t FrMaxSize = 77;
constexpr size_t FqMaxSize = 77;
#endif

_libff::_libff(void) :
    Module("libff") {
#if defined(LIBFF_HAVE_BLS12_381)
    libff::init_bls12_381_params();
    libff::init_edwards_params();
#else
    libff::init_alt_bn128_params();
#endif

    /*
    libff::init_mnt4_params();
    libff::init_mnt6_params();
    */

    libff::inhibit_profiling_info = true;
}

namespace libff_detail {
    template <class T>
    std::string ToString(const T& f) {
        std::string ret;
        mpz_t mp;
        mpz_init(mp);
        f.as_bigint().to_mpz(mp);
        char* str = mpz_get_str(nullptr, 10, mp);
        mpz_clear(mp);
        ret = std::string(str);
        free(str);
        return ret;
    }

    template <class Type>
    bool IsValid(const Type& point) {
        /* Curve check + group check */
        return point.is_well_formed() && (Type::order() * point == Type::zero());
    }
    std::optional<G1Type> Load(const component::G1& g1, Datasource& ds) {
        if ( g1.first.GetSize() > FqMaxSize ) return std::nullopt;
        if ( g1.second.GetSize() > FqMaxSize ) return std::nullopt;

        return G1Type(
                FqType(g1.first.ToString(ds).c_str()),
                FqType(g1.second.ToString(ds).c_str()),
                FqType::one()
        );
    }

    std::optional<G2Type> Load(const component::G2& g2, Datasource& ds) {
        if ( g2.first.first.GetSize() > FqMaxSize ) return std::nullopt;
        if ( g2.first.second.GetSize() > FqMaxSize ) return std::nullopt;
        if ( g2.second.first.GetSize() > FqMaxSize) return std::nullopt;
        if ( g2.second.second.GetSize() > FqMaxSize ) return std::nullopt;

        return G2Type(
                Fq2Type(
                    FqType(g2.first.first.ToString(ds).c_str()),
                    FqType(g2.second.first.ToString(ds).c_str())
                    ),
                Fq2Type(
                    FqType(g2.first.second.ToString(ds).c_str()),
                    FqType(g2.second.second.ToString(ds).c_str())
                    ),
                Fq2Type::one()
        );
    }

    component::G1 Save(G1Type& g1) {
        CF_NORET(g1.to_affine_coordinates());

        if ( g1.is_zero() ) {
            return component::G1{
                std::string("0"),
                std::string("0")
            };
        } else {
            return component::G1{
                libff_detail::ToString(g1.X),
                libff_detail::ToString(g1.Y),
            };
        }
    }

    component::G2 Save(G2Type& g2) {
        CF_NORET(g2.to_affine_coordinates());

        const auto V = libff_detail::ToString(g2.X.c0);
        const auto W = libff_detail::ToString(g2.Y.c0);
        const auto X = libff_detail::ToString(g2.X.c1);
        const auto Y = libff_detail::ToString(g2.Y.c1);

        if ( std::array<std::string, 4>{V, W, X, Y} == std::array<std::string, 4>{"0", "1", "0", "0"} ) {
            return component::G2{"0", "0", "0", "0"};
        }

        return component::G2{V, W, X, Y};
    }

    component::Fp12 Save(Fq12Type& fp12) {
        return component::Fp12{
            libff_detail::ToString(fp12.c0.c0.c0),
            libff_detail::ToString(fp12.c0.c0.c1),
            libff_detail::ToString(fp12.c0.c1.c0),
            libff_detail::ToString(fp12.c0.c1.c1),
            libff_detail::ToString(fp12.c0.c2.c0),
            libff_detail::ToString(fp12.c0.c2.c1),
            libff_detail::ToString(fp12.c1.c0.c0),
            libff_detail::ToString(fp12.c1.c0.c1),
            libff_detail::ToString(fp12.c1.c1.c0),
            libff_detail::ToString(fp12.c1.c1.c1),
            libff_detail::ToString(fp12.c1.c2.c0),
            libff_detail::ToString(fp12.c1.c2.c1),
        };
    }

    template <class Type, class Operation>
    std::optional<Type> Load(const Operation& op, Datasource& ds);

    template <>
    std::optional<G1Type> Load(const operation::BLS_IsG1OnCurve& op, Datasource& ds) {
        return Load(op.g1, ds);
    }

    template <>
    std::optional<G2Type> Load(const operation::BLS_IsG2OnCurve& op, Datasource& ds) {
        return Load(op.g2, ds);
    }

    template <class Type, class ReturnType>
    std::optional<ReturnType> Mul(const Type& a, const component::Bignum& multiplier, Datasource& ds) {
        std::optional<ReturnType> ret = std::nullopt;

        Type res;
        FrType b;

        CF_CHECK_LTE(multiplier.GetSize(), FrMaxSize);
        b = FrType(multiplier.ToString(ds).c_str());

        res = b * a;

        if ( b.is_zero() == true ) {
            CF_ASSERT(res.is_zero() == true, "Multiplication by 0 does not yield point at infinity");
            goto end;
        }

        CF_CHECK_TRUE(IsValid(a));

        ret = Save(res);

end:
        return ret;
    }

    template <class Type, class ReturnType>
    std::optional<ReturnType> Mul(const std::optional<Type>& a, const component::Bignum& multiplier, Datasource& ds) {
        return a == std::nullopt ? std::nullopt : Mul<Type, ReturnType>(*a, multiplier, ds);
    }

    template <class Type, class Operation>
    std::optional<bool> OpBLS_IsGxOnCurve(Operation& op) {
        std::optional<bool> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        std::optional<Type> point;

        CF_CHECK_NE((point = Load<Type, Operation>(op, ds)), std::nullopt);

        ret = IsValid(*point);

end:
        return ret;
    }

    template <class Type, class ReturnType, class Operation>
    std::optional<ReturnType> OpBLS_Gx_Add(Operation& op) {
        std::optional<ReturnType> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        std::optional<Type> a, b;
        Type res;

        CF_CHECK_NE(a = Load(op.a, ds), std::nullopt);
        CF_CHECK_NE(b = Load(op.b, ds), std::nullopt);

        res = *a + *b;

        CF_CHECK_TRUE(IsValid(*a));
        CF_CHECK_TRUE(IsValid(*b));
        CF_CHECK_TRUE(IsValid(res));

        ret = Save(res);

end:
        return ret;
    }

    template <class Type, class ReturnType, class Operation>
    std::optional<ReturnType> OpBLS_Gx_Mul(Operation& op) {
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        return Mul<Type, ReturnType>(
                Load(op.a, ds),
                op.b,
                ds
        );
    }

    template <class Type, class Operation>
    std::optional<bool> OpBLS_Gx_IsEq(Operation& op) {
        std::optional<bool> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        std::optional<Type> a, b;

        CF_CHECK_NE(a = Load(op.a, ds), std::nullopt);
        CF_CHECK_NE(b = Load(op.b, ds), std::nullopt);

        ret = *a == *b;

end:
        return ret;
    }

    template <class Type, class ReturnType, class Operation>
    std::optional<ReturnType> OpBLS_Gx_Neg(Operation& op) {
        std::optional<ReturnType> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        std::optional<Type> a;
        Type res;

        CF_CHECK_NE(a = Load(op.a, ds), std::nullopt);

        res = -(*a);

        CF_CHECK_TRUE(IsValid(*a));

        ret = Save(res);

end:
        return ret;
    }

} /* namespace libff_detail */

std::optional<component::BLS_PublicKey> _libff::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    return libff_detail::Mul<G1Type, component::BLS_PublicKey>(G1Type::one(), op.priv, ds);
}

std::optional<component::G2> _libff::OpBLS_PrivateToPublic_G2(operation::BLS_PrivateToPublic_G2& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    return libff_detail::Mul<G2Type, component::G2>(G2Type::one(), op.priv, ds);
}

std::optional<bool> _libff::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    return libff_detail::OpBLS_IsGxOnCurve<G1Type>(op);
}

std::optional<component::G1> _libff::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    return libff_detail::OpBLS_Gx_Add<G1Type, component::G1>(op);
}

std::optional<component::G1> _libff::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    return libff_detail::OpBLS_Gx_Mul<G1Type, component::G1>(op);
}

std::optional<bool> _libff::OpBLS_G1_IsEq(operation::BLS_G1_IsEq& op) {
    return libff_detail::OpBLS_Gx_IsEq<G1Type>(op);
}

std::optional<component::G1> _libff::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    return libff_detail::OpBLS_Gx_Neg<G1Type, component::G1>(op);
}

std::optional<bool> _libff::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    if (
            op.g2.first.first.ToTrimmedString() == "0" &&
            op.g2.first.second.ToTrimmedString() == "1" &&
            op.g2.second.first.ToTrimmedString() == "0" &&
            op.g2.second.second.ToTrimmedString() == "0" )
    {
        return true;
    }

    return libff_detail::OpBLS_IsGxOnCurve<G2Type>(op);
}

std::optional<component::G2> _libff::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    return libff_detail::OpBLS_Gx_Add<G2Type, component::G2>(op);
}

std::optional<component::G2> _libff::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    return libff_detail::OpBLS_Gx_Mul<G2Type, component::G2>(op);
}

std::optional<bool> _libff::OpBLS_G2_IsEq(operation::BLS_G2_IsEq& op) {
    return libff_detail::OpBLS_Gx_IsEq<G2Type>(op);
}

std::optional<component::G2> _libff::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    return libff_detail::OpBLS_Gx_Neg<G2Type, component::G2>(op);
}

std::optional<component::Fp12> _libff::OpBLS_FinalExp(operation::BLS_FinalExp& op) {
    std::optional<component::Fp12> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.fp12.bn1.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn2.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn3.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn4.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn5.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn6.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn7.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn8.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn9.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn10.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn11.GetSize() > FqMaxSize ) return std::nullopt;
    if ( op.fp12.bn12.GetSize() > FqMaxSize ) return std::nullopt;

    const auto f = Fq12Type(
            Fq6Type(
                Fq2Type(
                    FqType(op.fp12.bn1.ToTrimmedString().c_str()),
                    FqType(op.fp12.bn2.ToTrimmedString().c_str())
                    ),
                Fq2Type(
                    FqType(op.fp12.bn3.ToTrimmedString().c_str()),
                    FqType(op.fp12.bn4.ToTrimmedString().c_str())
                    ),
                Fq2Type(
                    FqType(op.fp12.bn5.ToTrimmedString().c_str()),
                    FqType(op.fp12.bn6.ToTrimmedString().c_str())
                    )
                ),
            Fq6Type(
                Fq2Type(
                    FqType(op.fp12.bn7.ToTrimmedString().c_str()),
                    FqType(op.fp12.bn8.ToTrimmedString().c_str())
                    ),
                Fq2Type(
                    FqType(op.fp12.bn9.ToTrimmedString().c_str()),
                    FqType(op.fp12.bn10.ToTrimmedString().c_str())
                    ),
                Fq2Type(
                    FqType(op.fp12.bn11.ToTrimmedString().c_str()),
                    FqType(op.fp12.bn12.ToTrimmedString().c_str())
                    )
                )
                );

    if ( f == Fq12Type::zero() ) {
        auto res = Fq12Type::zero();
        ret = libff_detail::Save(res);
        return ret;
    }

    {
#if defined(LIBFF_HAVE_BLS12_381)
        auto res = bls12_381_final_exponentiation(f);
#else
        auto res = alt_bn128_final_exponentiation(f);
#endif
        ret = libff_detail::Save(res);
    }

    return ret;
}

std::optional<bool> _libff::OpBLS_BatchVerify(operation::BLS_BatchVerify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    Fq12Type f = Fq12Type::one();

    for (const auto& cur : op.bf.c) {
        std::optional<G1Type> g1;
        std::optional<G2Type> g2;

        CF_CHECK_NE((g1 = libff_detail::Load(cur.g1, ds)), std::nullopt);
        CF_CHECK_NE((g2 = libff_detail::Load(cur.g2, ds)), std::nullopt);

        CF_CHECK_NE(g1->X, 0);
        CF_CHECK_NE(g1->Y, 0);

        CF_CHECK_NE(g2->X.c0, 0);
        CF_CHECK_NE(g2->X.c1, 0);
        CF_CHECK_NE(g2->Y.c0, 0);
        CF_CHECK_NE(g2->Y.c1, 0);

        CF_CHECK_TRUE(libff_detail::IsValid(*g1));
        CF_CHECK_TRUE(libff_detail::IsValid(*g2));

        f *=
#if defined(LIBFF_HAVE_BLS12_381)
            libff::bls12_381_pp::pairing(*g1, *g2);
#else
            libff::alt_bn128_pp::pairing(*g1, *g2);
#endif
    }

#if defined(LIBFF_HAVE_BLS12_381)
    ret = bls12_381_final_exponentiation(f) == Fq12Type::one();
#else
    ret = alt_bn128_final_exponentiation(f) == Fq12Type::one();
#endif

end:
    return ret;
}

std::optional<component::BLS_BatchSignature> _libff::OpBLS_BatchSign(operation::BLS_BatchSign& op) {
    std::optional<component::BLS_BatchSignature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    G1Type finalsig = G1Type::zero();

    std::vector< std::pair<component::G1, component::G2> > msgpub;

    for (const auto& cur : op.bf.c) {
        CF_CHECK_LTE(cur.priv.GetSize(), FrMaxSize);
        const auto priv = FrType(cur.priv.ToTrimmedString().c_str());

        auto pub = priv * G2Type::one();

        auto msg = libff_detail::Load(cur.g1, ds);
        CF_CHECK_NE(msg, std::nullopt);

        const auto signature = priv * *msg;

        {
            msg = -(*msg);
            pub = -pub;
            msgpub.push_back(
                    {
                        libff_detail::Save(*msg),
                        libff_detail::Save(pub)
                    }
            );
        }

        finalsig = finalsig + signature;
    }

    {
        finalsig = -finalsig;
        auto one_neg = -G2Type::one();
        msgpub.insert(
                msgpub.begin(),
                std::pair<component::G1, component::G2>{
                    libff_detail::Save(finalsig),
                    libff_detail::Save(one_neg)
                }
        );
    }

    ret = component::BLS_BatchSignature(msgpub);

end:
    return ret;
}

std::optional<component::Fp12> _libff::OpBLS_Pairing(operation::BLS_Pairing& op) {
    std::optional<component::Fp12> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<G1Type> g1;
    std::optional<G2Type> g2;

    CF_CHECK_NE((g1 = libff_detail::Load(op.g1, ds)), std::nullopt);
    CF_CHECK_NE((g2 = libff_detail::Load(op.g2, ds)), std::nullopt);

    CF_CHECK_NE(g1->X, 0);
    CF_CHECK_NE(g1->Y, 0);

    CF_CHECK_NE(g2->X.c0, 0);
    CF_CHECK_NE(g2->X.c1, 0);
    CF_CHECK_NE(g2->Y.c0, 0);
    CF_CHECK_NE(g2->Y.c1, 0);

    CF_CHECK_TRUE(libff_detail::IsValid(*g1));
    CF_CHECK_TRUE(libff_detail::IsValid(*g2));

    {
        auto paired =
#if defined(LIBFF_HAVE_BLS12_381)
            libff::bls12_381_pp::reduced_pairing(*g1, *g2);
#else
            libff::alt_bn128_pp::reduced_pairing(*g1, *g2);
#endif
        ret = libff_detail::Save(paired);
    }

end:
    return ret;
}

namespace libff_detail {
    template <class T, size_t MaxSize>
    std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) {
        std::optional<component::Bignum> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        if ( op.bn0.GetSize() >= MaxSize ) return std::nullopt;
        if ( op.bn1.GetSize() >= MaxSize  ) return std::nullopt;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto bn1 = T(op.bn1.ToTrimmedString().c_str());
                    const auto res = bn0 + bn1;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Sub(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto bn1 = T(op.bn1.ToTrimmedString().c_str());
                    const auto res = bn0 - bn1;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Mul(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto bn1 = T(op.bn1.ToTrimmedString().c_str());
                    const auto res = bn0 * bn1;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Exp(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto bn1 = T(op.bn1.ToTrimmedString().c_str());
                    const auto res = bn0 ^ bn1.as_bigint();
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    CF_CHECK_FALSE(bn0.is_zero());
                    const auto res = bn0.inverse();
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Sqr(A)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto res = bn0.squared();
                    CF_ASSERT(res.sqrt().squared() == res, "Sqr(Sqrt(A)) != A");
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Set(A)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    ret = component::Bignum{ ToString(bn0) };
                }
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto bn1 = T(op.bn1.ToTrimmedString().c_str());
                    ret = component::Bignum{ bn0 == bn1 ? std::string("1") : std::string("0") };
                }
                break;
            case    CF_CALCOP("IsZero(A)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    ret = component::Bignum{ bn0.is_zero() ? std::string("1") : std::string("0") };
                }
                break;
            case    CF_CALCOP("Sqrt(A)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto euler = bn0 ^ T::euler;
                    if ( euler == T::zero() || euler == T::one() ) {
                        const auto res = bn0.sqrt().squared();
                        ret = component::Bignum{ ToString(res) };
                    } else {
                        ret = component::Bignum{ std::string("0") };
                    }
                }
                break;
            case    CF_CALCOP("FrobeniusMap(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const boost::multiprecision::cpp_int bn1(op.bn1.ToTrimmedString());
                    CF_CHECK_LTE(bn1, std::numeric_limits<unsigned long>::max());
                    const auto res = bn0.Frobenius_map(bn1.convert_to<unsigned long>());
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Not(A)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto res = -bn0;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("LShift1(A)"):
                {
                    const auto bn0 = T(op.bn0.ToTrimmedString().c_str());
                    const auto res = bn0 * 2;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
        }
end:
        return ret;
    }
} /* namespace libff_detail */


std::optional<component::Bignum> _libff::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

#if defined(LIBFF_HAVE_BLS12_381)
    if ( op.modulo->ToTrimmedString() == "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        return libff_detail::OpBignumCalc<FrType, 77>(op);
    } else if ( op.modulo->ToTrimmedString() == "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        return libff_detail::OpBignumCalc<FqType, 115>(op);
    } else if ( op.modulo->ToTrimmedString() == "1552511030102430251236801561344621993261920897571225601" ) {
        return libff_detail::OpBignumCalc<libff::edwards_Fr, 55>(op);
    } else if ( op.modulo->ToTrimmedString() == "6210044120409721004947206240885978274523751269793792001" ) {
        return libff_detail::OpBignumCalc<libff::edwards_Fq, 55>(op);
#else
    if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088696311157297823662689037894645226208583" ) {
        return libff_detail::OpBignumCalc<libff::alt_bn128_Fq, 77>(op);
    } else if ( op.modulo->ToTrimmedString() == "21888242871839275222246405745257275088548364400416034343698204186575808495617" ) {
        return libff_detail::OpBignumCalc<libff::alt_bn128_Fr, 77>(op);
#endif
#if 0
    } else if ( op.modulo->ToTrimmedString() == "475922286169261325753349249653048451545124878552823515553267735739164647307408490559963137" ) {
        return libff_detail::OpBignumCalc<libff::mnt4_Fr, 90>(op);
    } else if ( op.modulo->ToTrimmedString() == "475922286169261325753349249653048451545124879242694725395555128576210262817955800483758081" ) {
        return libff_detail::OpBignumCalc<libff::mnt4_Fq, 90>(op);
    } else if ( op.modulo->ToTrimmedString() == "475922286169261325753349249653048451545124879242694725395555128576210262817955800483758081" ) {
        return libff_detail::OpBignumCalc<libff::mnt6_Fr, 90>(op);
    } else if ( op.modulo->ToTrimmedString() == "237961143084630662876674624826524225772562439621347362697777564288105131408977900241879040" ) {
        return libff_detail::OpBignumCalc<libff::mnt6_Fq, 90>(op);
#endif
    } else {
        return std::nullopt;
    }
}

bool _libff::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
