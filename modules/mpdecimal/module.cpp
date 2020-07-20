#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <mpdecimal.h>
#include "bn_ops.h"

extern "C" {
extern void *(* mpd_mallocfunc)(size_t size);
extern void *(* mpd_callocfunc)(size_t nmemb, size_t size);
extern void *(* mpd_reallocfunc)(void *ptr, size_t size);
extern void (* mpd_free)(void *ptr);
}

namespace cryptofuzz {
namespace module {

static void* mpdecimal_custom_malloc(size_t size) {
    return util::malloc(size);
}

static void* mpdecimal_custom_calloc(size_t A, size_t B) {
    const size_t size = A*B;
    void* p = util::malloc(size);
    if ( size ) {
        memset(p, 0x00, size);
    }
    return p;
}

static void* mpdecimal_custom_realloc(void* ptr, size_t size) {
    return util::realloc(ptr, size);
}

static void mpdecimal_custom_free(void* ptr) {
    util::free(ptr);
}

mpd_context_t ctx;

mpdecimal::mpdecimal(void) :
    Module("mpdecimal") {
        mpd_mallocfunc = mpdecimal_custom_malloc;
        mpd_callocfunc = mpdecimal_custom_calloc;
        mpd_reallocfunc = mpdecimal_custom_realloc;
        mpd_free = mpdecimal_custom_free;
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
        case    CF_CALCOP("And(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::And>();
            break;
        case    CF_CALCOP("Or(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Or>();
            break;
        case    CF_CALCOP("Xor(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Xor>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Cmp>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<mpdecimal_bignum::ExpMod>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            /* Disabled for now because mpdecimal's sqrt is ridiculously slow */
            /*
            opRunner = std::make_unique<mpdecimal_bignum::Sqrt>();
            */
            break;
        case    CF_CALCOP("MulAdd(A,B,C)"):
            opRunner = std::make_unique<mpdecimal_bignum::MulAdd>();
            break;
        case    CF_CALCOP("Min(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Min>();
            break;
        case    CF_CALCOP("Max(A,B)"):
            opRunner = std::make_unique<mpdecimal_bignum::Max>();
            break;
        case    CF_CALCOP("Log10(A)"):
            /* Disabled for now because mpdecimal's log10 is ridiculously slow */
            /*
            opRunner = std::make_unique<mpdecimal_bignum::Log10>();
            */
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
