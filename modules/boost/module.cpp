#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <limits>

namespace cryptofuzz {
namespace module {

Boost::Boost(void) :
    Module("Boost") { }

std::optional<component::Digest> Boost::OpDigest(operation::Digest& op) {
    using fuzzing::datasource::ID;

    std::optional<component::Digest> ret = std::nullopt;

    switch ( op.digestType.Get() ) {
        case CF_DIGEST("SHA1"):
            {
                boost::uuids::detail::sha1 sha1;
                sha1.process_bytes(op.cleartext.GetPtr(), op.cleartext.GetSize());
                unsigned int out[5];
                sha1.get_digest(out);
                uint8_t out2[20];

                memcpy(out2, out, sizeof(out2));
                for (size_t i = 0; i < 20; i += 4) {
                    uint8_t tmp;

                    tmp = out2[i+0];
                    out2[i+0] = out2[i+3];
                    out2[i+3] = tmp;

                    tmp = out2[i+1];
                    out2[i+1] = out2[i+2];
                    out2[i+2] = tmp;
                }

                ret = component::Digest(out2, 20);
            }
    }

    return ret;
}

std::optional<component::Bignum> Boost::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const boost::multiprecision::cpp_int bn0(op.bn0.ToTrimmedString());
    const boost::multiprecision::cpp_int bn1(op.bn1.ToTrimmedString());
    const boost::multiprecision::cpp_int bn2(op.bn2.ToTrimmedString());
    static const boost::multiprecision::cpp_int uint_max(static_cast<size_t>(std::numeric_limits<unsigned int>::max()));

    boost::multiprecision::cpp_int res;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            res = bn0 + bn1;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            res = bn0 - bn1;
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_NE(bn1, 0);
            res = bn0 / bn1;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            res = bn0 * bn1;
            break;
        case    CF_CALCOP("Mod(A,B)"):
            CF_CHECK_NE(bn1, 0);
            res = bn0 % bn1;
            break;
        case    CF_CALCOP("Sqrt(A)"):
            res = boost::multiprecision::sqrt(bn0);
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            CF_CHECK_LT(op.bn0.GetSize(), 100);
            CF_CHECK_LT(op.bn1.GetSize(), 100);
            CF_CHECK_LT(op.bn2.GetSize(), 100);

            CF_CHECK_NE(bn2, 0);
            res = boost::multiprecision::powm(bn0, bn1, bn2);
            break;
        case    CF_CALCOP("And(A,B)"):
            res = bn0 & bn1;
            break;
        case    CF_CALCOP("Or(A,B)"):
            res = bn0 | bn1;
            break;
        case    CF_CALCOP("Xor(A,B)"):
            res = bn0 ^ bn1;
            break;
        case    CF_CALCOP("LSB(A)"):
            CF_CHECK_NE(bn0, 0);
            res = boost::multiprecision::lsb(bn0);
            break;
        case    CF_CALCOP("MSB(A)"):
            CF_CHECK_NE(bn0, 0);
            res = boost::multiprecision::msb(bn0);
            break;
        case    CF_CALCOP("LShift1(A)"):
            res = bn0 << 1;
            break;
        case    CF_CALCOP("RShift(A,B)"):
            CF_CHECK_LTE(bn1, uint_max);
            res = bn0 >> static_cast<unsigned int>(bn1);
            break;
        case    CF_CALCOP("Bit(A,B)"):
            CF_CHECK_LTE(bn1, uint_max);
            res = boost::multiprecision::bit_test(bn0, static_cast<unsigned int>(bn1));
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            CF_CHECK_LTE(bn1, uint_max);
            res = bn0;
            res = boost::multiprecision::bit_set(res, static_cast<unsigned int>(bn1));
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            CF_CHECK_LTE(bn1, uint_max);
            res = bn0;
            res = boost::multiprecision::bit_unset(res, static_cast<unsigned int>(bn1));
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            res = bn0 == bn1;
            break;
        case    CF_CALCOP("IsGt(A,B)"):
            res = bn0 > bn1;
            break;
        case    CF_CALCOP("IsGte(A,B)"):
            res = bn0 >= bn1;
            break;
        case    CF_CALCOP("IsLt(A,B)"):
            res = bn0 < bn1;
            break;
        case    CF_CALCOP("IsLte(A,B)"):
            res = bn0 <= bn1;
            break;
        case    CF_CALCOP("IsZero(A)"):
            res = !bn0;
            break;
        default:
            goto end;
    }

    ret = res.str();

end:

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
