#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

libgmp::libgmp(void) :
    Module("libgmp") { }

std::optional<component::Bignum> libgmp::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<libgmp_bignum::Operation> opRunner = nullptr;

    std::vector<libgmp_bignum::Bignum> bn{
        libgmp_bignum::Bignum(),
        libgmp_bignum::Bignum(),
        libgmp_bignum::Bignum(),
        libgmp_bignum::Bignum()
    };
    libgmp_bignum::Bignum res;

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn[0].Set(op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn[1].Set(op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn[2].Set(op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn[3].Set(op.bn3.ToString(ds)), true);


    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Div>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::ExpMod>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::GCD>();
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Jacobi>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::LCM>();
            break;
        case    CF_CALCOP("Xor(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Xor>();
            break;
        case    CF_CALCOP("And(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::And>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<libgmp_bignum::Abs>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<libgmp_bignum::Neg>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);

    ret = res.ToComponentBignum();

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
