#include "module.h"
#include "bn_ops.h"
#include <cryptofuzz/util.h>

extern "C" {
    #include <relic_conf.h>
    #include <relic.h>
}

namespace cryptofuzz {
namespace module {

relic::relic(void) :
    Module("relic") {

    CF_ASSERT(core_init() == RLC_OK, "Cannot initialize relic");
}

namespace relic_detail {
    static bool SetCurve(const component::CurveType curveType) {

        /* TODO enable disabled curves in the relic build */

        switch ( curveType.Get() ) {
#if 0
            case    CF_ECC_CURVE("secp192r1"):
                /* noret */ ep_param_set(NIST_P192);
                return true;
#endif
#if 0
            case    CF_ECC_CURVE("secp224r1"):
                /* noret */ ep_param_set(NIST_P224);
                return true;
#endif
            case    CF_ECC_CURVE("secp256r1"):
                /* noret */ ep_param_set(NIST_P256);
                return true;
#if 0
            case    CF_ECC_CURVE("secp384r1"):
                /* noret */ ep_param_set(NIST_P384);
                return true;
#endif
            case    CF_ECC_CURVE("secp521r1"):
                /* noret */ ep_param_set(NIST_P521);
                return true;
            case    CF_ECC_CURVE("secp256k1"):
                /* noret */ ep_param_set(SECG_K256);
                return true;
            default:
                return false;
        }
    }
}

std::optional<component::ECC_PublicKey> relic::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    ec_t pub;
    relic_bignum::Bignum priv;

    /* Set curve */
    CF_CHECK_TRUE(relic_detail::SetCurve(op.curveType));

    /* Set privkey */
    CF_CHECK_TRUE(priv.Set(op.priv.ToString()));
    CF_CHECK_EQ(bn_is_zero(priv.Get()), 0);

    /* Compute pubkey */
    /* noret */ ec_new(pub);
	RLC_TRY {
        /* noret */ ec_mul_gen(pub, priv.Get());
    } RLC_CATCH_ANY {
        goto end;
    }
    CF_CHECK_NE(ec_is_infty(pub), 1);

    {
        const int size = ec_size_bin(pub, 0);
        CF_ASSERT(size > 1, "Pubkey has invalid size");
        CF_ASSERT((size % 2) == 1, "Pubkey has invalid size");
        uint8_t* out = util::malloc(size);
        ec_write_bin(out, size, pub, 0);

        CF_ASSERT(out[0] == 0x04, "pubkey not DER encoded");

        const auto halfSize = (size-1) / 2;
        const auto X = util::BinToDec(out + 1, halfSize);
        const auto Y = util::BinToDec(out + 1 + halfSize, halfSize);

        util::free(out);

        ret = {X, Y};
    }

end:
    return ret;
}

std::optional<component::Bignum> relic::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    relic_bignum::Bignum res;
    std::vector<relic_bignum::Bignum> bn(4);

    std::unique_ptr<relic_bignum::Operation> opRunner = nullptr;

    CF_CHECK_TRUE(res.Set("0"));
    CF_CHECK_TRUE(bn[0].Set(op.bn0.ToString(ds)));
    CF_CHECK_TRUE(bn[1].Set(op.bn1.ToString(ds)));
    CF_CHECK_TRUE(bn[2].Set(op.bn2.ToString(ds)));
    CF_CHECK_TRUE(bn[3].Set(op.bn3.ToString(ds)));

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<relic_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<relic_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<relic_bignum::Mul>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<relic_bignum::Sqr>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<relic_bignum::Div>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<relic_bignum::GCD>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<relic_bignum::LCM>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<relic_bignum::InvMod>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<relic_bignum::LShift1>();
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<relic_bignum::Jacobi>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<relic_bignum::Cmp>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<relic_bignum::Mod>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<relic_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<relic_bignum::IsOdd>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<relic_bignum::IsZero>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<relic_bignum::Neg>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<relic_bignum::Sqrt>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<relic_bignum::Abs>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<relic_bignum::ExpMod>();
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
