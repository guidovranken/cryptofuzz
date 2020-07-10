#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_bignum {

bool Add::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_add(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Sub::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_sub(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_mul(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Div::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_div(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr(), nullptr), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_exptmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);

    if (
            !mp_iszero(bn[1].GetPtr()) &&
            !mp_isneg(bn[0].GetPtr()) &&
            !mp_isneg(bn[1].GetPtr()) &&
            !mp_isneg(bn[2].GetPtr()) ) {
            ret = true;
    }

end:
    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_sqr(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    bool ret = false;

    CF_CHECK_EQ(mp_gcd(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_invmod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    const int cmpRes = mp_cmp(bn[0].GetPtr(), bn[1].GetPtr());

    switch ( cmpRes ) {
        case    MP_GT:
            res.Set("1");
            break;
        case    MP_LT:
            res.Set("-1");
            break;
        case    MP_EQ:
            res.Set("0");
            break;
        default:
            /* Invalid return value */
            abort();
    }

    return true;
}

bool Abs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_abs(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Neg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool RShift::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool LShift1::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mp_isneg(bn[0].GetPtr()) ? 1 : 0) );

    bool ret = false;

    return ret;
}

bool IsEq::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    const bool isEq = mp_cmp(bn[0].GetPtr(), bn[1].GetPtr()) == MP_EQ;
    res.Set( std::to_string(isEq ? 1 : 0) );

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mp_iszero(bn[0].GetPtr()) ? 1 : 0) );

    bool ret = false;

    return ret;
}

bool IsOne::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mp_isone(bn[0].GetPtr()) ? 1 : 0) );

    bool ret = false;

    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_mulmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_addmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_submod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_sqrmod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool SetBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool ClearBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool LCM::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_lcm(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Mod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_mod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool IsEven::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mp_iseven(bn[0].GetPtr()) ? 1 : 0) );

    bool ret = false;

    return ret;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mp_isodd(bn[0].GetPtr()) ? 1 : 0) );

    bool ret = false;

    return ret;
}

} /* namespace wolfCrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
