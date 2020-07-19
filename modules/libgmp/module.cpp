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
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Cmp>();
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
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<libgmp_bignum::Sqrt>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<libgmp_bignum::Sqr>();
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::CmpAbs>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsNeg>();
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::AddMod>();
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::SubMod>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::MulMod>();
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::SqrMod>();
            break;
        case    CF_CALCOP("Mod_NIST_192(A)"):
            opRunner = std::make_unique<libgmp_bignum::Mod_NIST_192>();
            break;
        case    CF_CALCOP("Mod_NIST_224(A)"):
            opRunner = std::make_unique<libgmp_bignum::Mod_NIST_224>();
            break;
        case    CF_CALCOP("Mod_NIST_256(A)"):
            opRunner = std::make_unique<libgmp_bignum::Mod_NIST_256>();
            break;
        case    CF_CALCOP("Mod_NIST_384(A)"):
            opRunner = std::make_unique<libgmp_bignum::Mod_NIST_384>();
            break;
        case    CF_CALCOP("Mod_NIST_521(A)"):
            opRunner = std::make_unique<libgmp_bignum::Mod_NIST_521>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::SetBit>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::ClearBit>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Bit>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::InvMod>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsOdd>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsPow2(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsPow2>();
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
