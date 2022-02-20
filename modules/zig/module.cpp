#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
extern "C" {
size_t cryptofuzz_zig_bignumcalc(
        char* res_data, const size_t res_size,
        const char* a_data, const size_t a_size,
        const char* b_data, const size_t b_size,
        size_t operation);
}

namespace cryptofuzz {
namespace module {

Zig::Zig(void) :
    Module("Zig") { }

std::optional<component::Bignum> Zig::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint64_t operation = 0;

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            operation = 0;
            break;
        case    CF_CALCOP("Sub(A,B)"):
            operation = 1;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            operation = 2;
            break;
        case    CF_CALCOP("Div(A,B)"):
            operation = 3;
            break;
        case    CF_CALCOP("GCD(A,B)"):
            operation = 4;
            break;
        case    CF_CALCOP("Sqr(A)"):
            operation = 5;
            break;
        case    CF_CALCOP("Mod(A,B)"):
            operation = 6;
            break;
        case    CF_CALCOP("LShift1(A)"):
            operation = 7;
            break;
        case    CF_CALCOP("And(A,B)"):
            operation = 8;
            break;
        case    CF_CALCOP("Or(A,B)"):
            operation = 9;
            break;
        case    CF_CALCOP("Xor(A,B)"):
            operation = 10;
            break;
        case    CF_CALCOP("Neg(A)"):
            operation = 11;
            break;
        case    CF_CALCOP("Abs(A)"):
            operation = 12;
            break;
        case    CF_CALCOP("NumBits(A)"):
            operation = 13;
            break;
        case    CF_CALCOP("RShift(A,B)"):
            operation = 14;
            break;
        case    CF_CALCOP("Exp(A,B)"):
            operation = 15;
            break;
        default:
            return std::nullopt;
    }

    char res[8192];
    const auto bn0 = op.bn0.ToTrimmedString();
    const auto bn1 = op.bn1.ToTrimmedString();

    memset(res, 0, sizeof(res));
    CF_CHECK_EQ(cryptofuzz_zig_bignumcalc(
            res, sizeof(res),
            bn0.c_str(), bn0.size(),
            bn1.c_str(), bn1.size(),
            operation), 0);

    ret = std::string(res); 
end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
