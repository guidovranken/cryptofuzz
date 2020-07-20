#include "module.h"
#include <cryptofuzz/util.h>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

libtommath::libtommath(void) :
    Module("libtommath") {
}

std::optional<component::Bignum> libtommath::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<libtommath_bignum::Operation> opRunner = nullptr;

    std::vector<libtommath_bignum::Bignum> bn{
        libtommath_bignum::Bignum(),
        libtommath_bignum::Bignum(),
        libtommath_bignum::Bignum(),
        libtommath_bignum::Bignum()
    };
    libtommath_bignum::Bignum res;

    CF_CHECK_EQ(res.Set("0"), true);
#if 0
    CF_CHECK_EQ(bn[0].Set(op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn[1].Set(op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn[2].Set(op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn[3].Set(op.bn3.ToString(ds)), true);
#endif
    CF_CHECK_EQ(bn[0].Set(op.bn0.ToTrimmedString()), true);
    CF_CHECK_EQ(bn[1].Set(op.bn1.ToTrimmedString()), true);
    CF_CHECK_EQ(bn[2].Set(op.bn2.ToTrimmedString()), true);
    CF_CHECK_EQ(bn[3].Set(op.bn3.ToTrimmedString()), true);


    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Div>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::GCD>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::LCM>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Mod>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<libtommath_bignum::ExpMod>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<libtommath_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<libtommath_bignum::IsOdd>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<libtommath_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<libtommath_bignum::IsNeg>();
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<libtommath_bignum::AddMod>();
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<libtommath_bignum::SubMod>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<libtommath_bignum::MulMod>();
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::SqrMod>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::InvMod>();
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Jacobi>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<libtommath_bignum::Sqrt>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Cmp>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<libtommath_bignum::Neg>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<libtommath_bignum::Abs>();
            break;
        case    CF_CALCOP("And(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::And>();
            break;
        case    CF_CALCOP("Or(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Or>();
            break;
        case    CF_CALCOP("Xor(A,B)"):
            opRunner = std::make_unique<libtommath_bignum::Xor>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<libtommath_bignum::Sqr>();
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
