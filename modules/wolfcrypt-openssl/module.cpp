#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

wolfCrypt_OpenSSL::wolfCrypt_OpenSSL(void) :
    Module("wolfCrypt-OpenSSL") {
}

std::optional<component::Bignum> wolfCrypt_OpenSSL::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    OpenSSL_bignum::BN_CTX ctx(ds);
    OpenSSL_bignum::BignumCluster bn(ds,
        OpenSSL_bignum::Bignum(ds),
        OpenSSL_bignum::Bignum(ds),
        OpenSSL_bignum::Bignum(ds),
        OpenSSL_bignum::Bignum(ds));
    OpenSSL_bignum::Bignum res(ds);
    std::unique_ptr<OpenSSL_bignum::Operation> opRunner = nullptr;

    CF_CHECK_EQ(res.New(), true);
    CF_CHECK_EQ(bn.New(0), true);
    CF_CHECK_EQ(bn.New(1), true);
    CF_CHECK_EQ(bn.New(2), true);
    CF_CHECK_EQ(bn.New(3), true);

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sub>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mul>();
            break;
#endif
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::ExpMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sqr>();
            break;
#endif
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::GCD>();
            break;
#endif
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::AddMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::SubMod>();
            break;
#endif
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::MulMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SqrMod>();
            break;
#endif
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Cmp>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Div>();
            break;
#endif
        case    CF_CALCOP("IsPrime(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsPrime>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sqrt>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsNeg>();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsEq>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsOdd>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsOne(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsOne>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Jacobi>();
            break;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Mod_NIST_192(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_192>();
            break;
        case    CF_CALCOP("Mod_NIST_224(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_224>();
            break;
        case    CF_CALCOP("Mod_NIST_256(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_256>();
            break;
        case    CF_CALCOP("Mod_NIST_384(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_384>();
            break;
        case    CF_CALCOP("Mod_NIST_521(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_521>();
            break;
#endif
        case    CF_CALCOP("SqrtMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SqrtMod>();
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::LCM>();
            break;
#endif
        case    CF_CALCOP("Exp(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Exp>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Abs>();
            break;
        case    CF_CALCOP("RShift(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::RShift>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::LShift1>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SetBit>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::ClearBit>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Bit>();
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::CmpAbs>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("ModLShift(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::ModLShift>();
            break;
#endif
        case    CF_CALCOP("IsPow2(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsPow2>();
            break;
        case    CF_CALCOP("Mask(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mask>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn, ctx), true);

    ret = res.ToComponentBignum();

#if defined(CRYPTOFUZZ_WOLFCRYPT)
    switch ( op.calcOp.Get() ) {
        /* Wrong results */
        case    CF_CALCOP("Cmp(A,B)"):
            return std::nullopt;
    }
#endif

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
