#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

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
constexpr size_t FrMaxSize = 77;
constexpr size_t FqMaxSize = 115;
#else
using G1Type = libff::alt_bn128_G1;
using G2Type = libff::alt_bn128_G2;
using FrType = libff::alt_bn128_Fr;
using FqType = libff::alt_bn128_Fq;
using Fq2Type = libff::alt_bn128_Fq2;
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

    //libff::inhibit_profiling_info = true;
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

        return component::G1{
            libff_detail::ToString(g1.X),
            libff_detail::ToString(g1.Y),
        };
    }

    component::G2 Save(G2Type& g2) {
        CF_NORET(g2.to_affine_coordinates());

        return component::G2{
            libff_detail::ToString(g2.X.c0), libff_detail::ToString(g2.Y.c0),
            libff_detail::ToString(g2.X.c1), libff_detail::ToString(g2.Y.c1),
        };
    }

} /* namespace libff_detail */

namespace libff_detail {
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
        std::optional<ReturnType> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        std::optional<Type> a;
        FrType b;
        Type res;

        CF_CHECK_LTE(op.b.GetSize(), FrMaxSize);
        CF_CHECK_NE(a = Load(op.a, ds), std::nullopt);
        b = FrType(op.b.ToString(ds).c_str());

        res = b * *a;

        CF_CHECK_TRUE(IsValid(*a));
        CF_CHECK_FALSE(b.is_zero());

        ret = Save(res);

end:
        return ret;
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
} /* namespace libff_detail */

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

std::optional<bool> _libff::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
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
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    const auto bn1 = T(op.bn1.ToString(ds).c_str());
                    const auto res = bn0 + bn1;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Sub(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    const auto bn1 = T(op.bn1.ToString(ds).c_str());
                    const auto res = bn0 - bn1;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Mul(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    const auto bn1 = T(op.bn1.ToString(ds).c_str());
                    const auto res = bn0 * bn1;
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Exp(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    const auto bn1 = T(op.bn1.ToString(ds).c_str());
                    const auto res = bn0 ^ bn1.as_bigint();
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    CF_CHECK_FALSE(bn0.is_zero());
                    const auto res = bn0.inverse();
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Sqr(A)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    const auto res = bn0.squared();
                    if ( !bn0.is_zero() ) {
                        CF_ASSERT(res.sqrt().squared() == res, "Sqr(Sqrt(A)) != A");
                    }
                    ret = component::Bignum{ ToString(res) };
                }
                break;
            case    CF_CALCOP("Set(A)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    ret = component::Bignum{ ToString(bn0) };
                }
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    const auto bn1 = T(op.bn1.ToString(ds).c_str());
                    ret = component::Bignum{ bn0 == bn1 ? std::string("1") : std::string("0") };
                }
                break;
            case    CF_CALCOP("IsZero(A)"):
                {
                    const auto bn0 = T(op.bn0.ToString(ds).c_str());
                    ret = component::Bignum{ bn0.is_zero() ? std::string("1") : std::string("0") };
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
