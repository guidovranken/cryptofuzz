#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <mpdecimal.h>
#include "bn_ops.h"

namespace cryptofuzz {
namespace module {

mpd_context_t ctx;

mpdecimal::mpdecimal(void) :
    Module("mpdecimal") {
    mpd_init(&ctx, 100000);
}

std::optional<component::Bignum> mpdecimal::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::unique_ptr<mpdecimal_bignum::Operation> opRunner = nullptr;

    std::vector<mpdecimal_bignum::Bignum> bn{
        std::move(mpdecimal_bignum::Bignum(&ctx)),
        std::move(mpdecimal_bignum::Bignum(&ctx)),
        std::move(mpdecimal_bignum::Bignum(&ctx)),
        std::move(mpdecimal_bignum::Bignum(&ctx)),
    };
    mpdecimal_bignum::Bignum res(&ctx);

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn[0].Set(op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn[1].Set(op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn[2].Set(op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn[3].Set(op.bn3.ToString(ds)), true);

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Div>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<mpdecimal_bignum::Abs>();
            break;
        case    CF_CALCOP("Xor(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Abs>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Cmp>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn, &ctx), true);

    ret = res.ToComponentBignum();

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
