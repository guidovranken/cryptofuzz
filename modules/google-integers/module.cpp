#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <limits>
#include <trapping.h>

namespace cryptofuzz {
namespace module {

Google_Integers::Google_Integers(void) :
    Module("Google-Integers") { }

namespace Google_Integers_detail {
    template <class T>
    std::optional<integers::trapping<T>> Load(const Bignum& bn, const boost::multiprecision::cpp_int& max) {
        const boost::multiprecision::cpp_int _bn(bn.ToTrimmedString());
        if ( _bn > max ) {
            return std::nullopt;
        }

        return integers::trapping<T>(static_cast<T>(_bn));
    }

    template <class T>
    std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) {
        std::optional<component::Bignum> ret = std::nullopt;

        const boost::multiprecision::cpp_int max(static_cast<size_t>(std::numeric_limits<T>::max()));
        std::optional<integers::trapping<T>> bn0, bn1;
        T res = 0;

        CF_CHECK_NE(bn0 = Load<T>(op.bn0, max), std::nullopt);
        CF_CHECK_NE(bn1 = Load<T>(op.bn1, max), std::nullopt);

        try {
            switch ( op.calcOp.Get() ) {
                case    CF_CALCOP("Add(A,B)"):
                    res = *bn0 + *bn1;
                    break;
                case    CF_CALCOP("Sub(A,B)"):
                    res = *bn0 - *bn1;
                    break;
                case    CF_CALCOP("Mul(A,B)"):
                    res = *bn0 * *bn1;
                    break;
                case    CF_CALCOP("Div(A,B)"):
                    res = *bn0 / *bn1;
                    break;
                case    CF_CALCOP("Mod(A,B)"):
                    res = *bn0 % *bn1;
                    break;
                case    CF_CALCOP("LShift1(A)"):
                    res = *bn0 << integers::trapping<T>(1);
                    break;
                case    CF_CALCOP("RShift(A,B)"):
                    res = *bn0 >> *bn1;
                    break;
                case    CF_CALCOP("And(A,B)"):
                    res = *bn0 & *bn1;
                    break;
                case    CF_CALCOP("Or(A,B)"):
                    res = *bn0 | *bn1;
                    break;
                case    CF_CALCOP("Xor(A,B)"):
                    res = *bn0 ^ *bn1;
                    break;
                case    CF_CALCOP("IsNeg(A)"):
                    res = *bn0 < integers::trapping<T>(0);
                    break;
                case    CF_CALCOP("IsEq(A,B)"):
                    res = *bn0 == *bn1;
                    break;
                case    CF_CALCOP("IsGt(A,B)"):
                    res = *bn0 > *bn1;
                    break;
                case    CF_CALCOP("IsGte(A,B)"):
                    res = *bn0 >= *bn1;
                    break;
                case    CF_CALCOP("IsLt(A,B)"):
                    res = *bn0 < *bn1;
                    break;
                case    CF_CALCOP("IsLte(A,B)"):
                    res = *bn0 <= *bn1;
                    break;
                case    CF_CALCOP("IsZero(A)"):
                    res = *bn0 == integers::trapping<T>(0);
                    break;
                case    CF_CALCOP("IsOne(A)"):
                    res = *bn0 == integers::trapping<T>(1);
                    break;
                default:
                    goto end;
            }
        } catch ( std::runtime_error& ) {
            goto end;
        }

        ret = std::to_string(res);

end:
        return ret;
    }
}

std::optional<component::Bignum> Google_Integers::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                return Google_Integers_detail::OpBignumCalc<uint8_t>(op);
            case    1:
                return Google_Integers_detail::OpBignumCalc<uint16_t>(op);
            case    2:
                return Google_Integers_detail::OpBignumCalc<uint32_t>(op);
            case    3:
                return Google_Integers_detail::OpBignumCalc<uint64_t>(op);

            case    4:
                return Google_Integers_detail::OpBignumCalc<int8_t>(op);
            case    5:
                return Google_Integers_detail::OpBignumCalc<int16_t>(op);
            case    6:
                return Google_Integers_detail::OpBignumCalc<int32_t>(op);
            case    7:
                return Google_Integers_detail::OpBignumCalc<int64_t>(op);
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
