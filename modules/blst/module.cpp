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
}

std::optional<component::BLS_PublicKey> blst::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<component::BLS_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    return ret;
}

namespace blst_detail {
    std::optional<component::Bignum> OpBignumCalc_order(operation::BignumCalc& op) {
        std::optional<component::Bignum> ret = std::nullopt;
        blst_fr result, A, B;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                blst_fr_add(&result, &A, &B);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("Sub(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                blst_fr_sub(&result, &A, &B);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("Mul(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn1, B));
                if ( op.bn1.ToTrimmedString() == "3" ) {
                    blst_fr_mul_by_3(&result, &A);
                } else {
                    blst_fr_mul(&result, &A, &B);
                }
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("Sqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                blst_fr_sqr(&result, &A);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                blst_fr_eucl_inverse(&result, &A);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("LShift1(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                blst_fr_lshift(&result, &A, 1);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("RShift(A,B)"):
                {
                    CF_CHECK_TRUE(blst_detail::To_blst_fr(op.bn0, A));
                    const auto B_cpp_int = blst_detail::To_cpp_int(op.bn1);
                    size_t count = static_cast<size_t>(B_cpp_int);
                    CF_CHECK_EQ(count, B_cpp_int);
                    CF_CHECK_GT(count, 0);
                    CF_CHECK_LT(count, 10);
                    CF_CHECK_EQ(count, 1);
                    blst_fr_rshift(&result, &A, count);
                    ret = blst_detail::To_component_bignum(result);
                }
                break;
        }

end:
        return ret;
    }

    std::optional<component::Bignum> OpBignumCalc_prime(operation::BignumCalc& op) {
        std::optional<component::Bignum> ret = std::nullopt;
        blst_fp result, A, B;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                blst_fp_add(&result, &A, &B);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("Sub(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                blst_fp_sub(&result, &A, &B);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("Mul(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn1, B));
                if ( op.bn1.ToTrimmedString() == "3" ) {
                    blst_fp_mul_by_3(&result, &A);
                } else if ( op.bn1.ToTrimmedString() == "8" ) {
                    blst_fp_mul_by_8(&result, &A);
                } else {
                    blst_fp_mul(&result, &A, &B);
                }
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("LShift1(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                blst_fp_lshift(&result, &A, 1);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("Sqr(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                blst_fp_sqr(&result, &A);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                blst_fp_eucl_inverse(&result, &A);
                ret = blst_detail::To_component_bignum(result);
                break;
            case    CF_CALCOP("Sqrt(A)"):
                CF_CHECK_TRUE(blst_detail::To_blst_fp(op.bn0, A));
                blst_fp_sqr(&result, &A);
                //ret = blst_detail::To_component_bignum(result);
                break;
        }

end:
        return ret;
    }
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

bool blst::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
