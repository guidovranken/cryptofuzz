#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

#if !defined(HAVE_MINI_GMP)
namespace libgmp_detail {
    gmp_randstate_t rng_state;
}
#endif

libgmp::libgmp(void) :
    Module("libgmp") {
#if !defined(HAVE_MINI_GMP)
    /* noret */ gmp_randinit_default(libgmp_detail::rng_state);
    /* noret */ gmp_randseed_ui(libgmp_detail::rng_state, rand());
#endif
}

std::optional<component::Bignum> libgmp::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    std::unique_ptr<libgmp_bignum::Operation> opRunner = nullptr;

    libgmp_bignum::BignumCluster bn{ds,
        libgmp_bignum::Bignum(),
        libgmp_bignum::Bignum(),
        libgmp_bignum::Bignum(),
        libgmp_bignum::Bignum()
    };
    libgmp_bignum::Bignum res;

    if ( op.calcOp.Is(CF_CALCOP("Set(A)")) ) {
        CF_CHECK_EQ(res.Set("0"), true);
    } else {
        CF_NORET(res.Randomize(ds));
    }
    CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);


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
        case    CF_CALCOP("ExtGCD_X(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::ExtGCD_X>();
            break;
        case    CF_CALCOP("ExtGCD_Y(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::ExtGCD_Y>();
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
        case    CF_CALCOP("SqrtCeil(A)"):
            opRunner = std::make_unique<libgmp_bignum::SqrtCeil>();
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
        case    CF_CALCOP("NumLSZeroBits(A)"):
            opRunner = std::make_unique<libgmp_bignum::NumLSZeroBits>();
            break;
        case    CF_CALCOP("Factorial(A)"):
            opRunner = std::make_unique<libgmp_bignum::Factorial>();
            break;
        case    CF_CALCOP("Cbrt(A)"):
            opRunner = std::make_unique<libgmp_bignum::Cbrt>();
            break;
        case    CF_CALCOP("SqrtRem(A)"):
            opRunner = std::make_unique<libgmp_bignum::SqrtRem>();
            break;
        case    CF_CALCOP("CbrtRem(A)"):
            opRunner = std::make_unique<libgmp_bignum::CbrtRem>();
            break;
        case    CF_CALCOP("Nthrt(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Nthrt>();
            break;
        case    CF_CALCOP("NthrtRem(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::NthrtRem>();
            break;
        case    CF_CALCOP("IsSquare(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsSquare>();
            break;
        case    CF_CALCOP("Exp(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Exp>();
            break;
        case    CF_CALCOP("Or(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Or>();
            break;
        case    CF_CALCOP("AddMul(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::AddMul>();
            break;
        case    CF_CALCOP("SubMul(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::SubMul>();
            break;
        case    CF_CALCOP("Primorial(A)"):
            opRunner = std::make_unique<libgmp_bignum::Primorial>();
            break;
        case    CF_CALCOP("Lucas(A)"):
            opRunner = std::make_unique<libgmp_bignum::Lucas>();
            break;
        case    CF_CALCOP("Fibonacci(A)"):
            opRunner = std::make_unique<libgmp_bignum::Fibonacci>();
            break;
        case    CF_CALCOP("Set(A)"):
            opRunner = std::make_unique<libgmp_bignum::Set>();
            break;
        case    CF_CALCOP("BinCoeff(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::BinCoeff>();
            break;
        case    CF_CALCOP("HamDist(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::HamDist>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::Mod>();
            break;
        case    CF_CALCOP("IsPower(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsPower>();
            break;
        case    CF_CALCOP("Prime()"):
            opRunner = std::make_unique<libgmp_bignum::Prime>();
            break;
        case    CF_CALCOP("IsPrime(A)"):
            opRunner = std::make_unique<libgmp_bignum::IsPrime>();
            break;
        case    CF_CALCOP("Rand()"):
            opRunner = std::make_unique<libgmp_bignum::Rand>();
            break;
        case    CF_CALCOP("NumBits(A)"):
            opRunner = std::make_unique<libgmp_bignum::NumBits>();
            break;
        case    CF_CALCOP("CondAdd(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::CondAdd>();
            break;
        case    CF_CALCOP("CondSub(A,B,C)"):
            opRunner = std::make_unique<libgmp_bignum::CondSub>();
            break;
        case    CF_CALCOP("RandRange(A,B)"):
            opRunner = std::make_unique<libgmp_bignum::RandRange>();
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
