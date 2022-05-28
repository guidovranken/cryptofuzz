#include "module.h"
#include <intx/intx.hpp>
#include <cryptofuzz/util.h>

namespace cryptofuzz {
namespace module {

intx::intx(void) :
    Module("intx") { }

namespace intx_detail {
    template <class T, size_t Size>
        std::optional<component::Bignum> OpBignumCalc(operation::BignumCalc& op) {
            std::optional<component::Bignum> ret = std::nullopt;
            Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

            uint8_t result[Size] = {0};
            std::optional<std::vector<uint8_t>> _bn0, _bn1, _bn2;
            T res, bn0, bn1, bn2; 

            CF_CHECK_NE(_bn0 = util::DecToBin(op.bn0.ToTrimmedString(), Size), std::nullopt);
            CF_CHECK_NE(_bn1 = util::DecToBin(op.bn1.ToTrimmedString(), Size), std::nullopt);
            CF_CHECK_NE(_bn2 = util::DecToBin(op.bn2.ToTrimmedString(), Size), std::nullopt);

            /* TODO alternatively initialize from dec/hex strings */
            bn0 = ::intx::be::unsafe::load<T>(_bn0->data());
            bn1 = ::intx::be::unsafe::load<T>(_bn1->data());
            bn2 = ::intx::be::unsafe::load<T>(_bn2->data());

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
                case    CF_CALCOP("Exp(A,B)"):
                    res = ::intx::exp(bn0, bn1);
                    break;
                case    CF_CALCOP("LShift(A)"):
                    res = bn0 << bn1;
                    break;
                case    CF_CALCOP("LShift1(A)"):
                    res = bn0 << 1;
                    break;
                case    CF_CALCOP("RShift(A,B)"):
                    res = bn0 >> bn1;
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
                case    CF_CALCOP("IsEq(A,B)"):
                    res = bn0 == bn1;
                    break;
                case    CF_CALCOP("IsLt(A,B)"):
                    res = bn0 < bn1;
                    break;
                case    CF_CALCOP("IsLte(A,B)"):
                    res = bn0 <= bn1;
                    break;
                case    CF_CALCOP("IsGt(A,B)"):
                    res = bn0 > bn1;
                    break;
                case    CF_CALCOP("IsGte(A,B)"):
                    res = bn0 >= bn1;
                    break;
                case    CF_CALCOP("NumLSZeroBits(A)"):
                    res = ::intx::clz(bn0);
                    break;
                case    CF_CALCOP("Set(A)"):
                    res = bn0;
                    break;
                case    CF_CALCOP("Not(A)"):
                    res = ~(bn0-1);
                    break;
                case    CF_CALCOP("Min(A,B)"):
                    res = bn0 < bn1 ? bn0 : bn1;
                    break;
                case    CF_CALCOP("Max(A,B)"):
                    res = bn0 > bn1 ? bn0 : bn1;
                    break;
                case    CF_CALCOP("AddMod(A,B,C)"):
                    CF_CHECK_NE(bn2, 0);

                    if constexpr (std::is_same_v<T, ::intx::uint256>) {
                        res = ::intx::addmod(bn0, bn1, bn2);
                    } else {
                        goto end;
                    }
                    break;
                case    CF_CALCOP("MulMod(A,B,C)"):
                    CF_CHECK_NE(bn2, 0);

                    if constexpr (std::is_same_v<T, ::intx::uint256>) {
                        res = ::intx::mulmod(bn0, bn1, bn2);
                    } else {
                        goto end;
                    }
                    break;
                case    CF_CALCOP("SDiv(A,B)"):
                    CF_CHECK_NE(bn1, 0);
                    res = sdivrem(bn0, bn1).quot;
                    break;
                default:
                    goto end;
            }

            {
                bool convert = false;
                bool hex = false;
                try {
                    convert = ds.Get<bool>();
                    if ( convert ) {
                        hex = ds.Get<bool>();
                    }
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( convert ) {
                    auto s = hex ? ::intx::hex(res) : ::intx::to_string(res);
                    s = (hex ? std::string("0x") : std::string("")) + s;
                    res = ::intx::from_string<T>(s);
                }
            }

            CF_NORET(::intx::be::unsafe::store(result, res));
            ret = util::BinToDec(result, sizeof(result));

end:
            return ret;
        }
}

std::optional<component::Bignum> intx::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    } else if ( op.modulo->ToTrimmedString() == "340282366920938463463374607431768211456" ) {
        return intx_detail::OpBignumCalc<::intx::uint128, 16>(op);
    } else if ( op.modulo->ToTrimmedString() == "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
        return intx_detail::OpBignumCalc<::intx::uint256, 32>(op);
    } else if ( op.modulo->ToTrimmedString() == "13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084096" ) {
        return intx_detail::OpBignumCalc<::intx::uint512, 64>(op);
    } else {
        return std::nullopt;
    }

}

bool intx::SupportsModularBignumCalc(void) const {
    return true;
}
} /* namespace module */
} /* namespace cryptofuzz */
