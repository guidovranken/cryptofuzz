#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
    void rt_init();
    char* cryptofuzz_d_bignumcalc(
            const char* bn0str,
            const char* bn1str,
            const char* bn2str,
            const uint64_t calcOp);
}

namespace cryptofuzz {
namespace module {

D::D(void) :
    Module("D") {
    rt_init();
}

std::optional<component::Bignum> D::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    const auto res = cryptofuzz_d_bignumcalc(
            op.bn0.ToTrimmedString().c_str(),
            op.bn1.ToTrimmedString().c_str(),
            op.bn2.ToTrimmedString().c_str(),
            op.calcOp.Get());
    if ( res != nullptr ) {
        ret = component::Bignum(std::string(res));
        free(res);
    }
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
