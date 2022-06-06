#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"
extern "C" {
#include <ecl/ecl-priv.h>
}

namespace cryptofuzz {
namespace module {
namespace NSS_bignum {

ECGroup* nist_p256 = nullptr;
ECGroup* nist_p384 = nullptr;
ECGroup* nist_p521 = nullptr;

void Initialize(void) {
    bool ok = false;

    CF_CHECK_NE(nist_p256 = ECGroup_fromName(ECCurve_NIST_P256), nullptr);
    CF_CHECK_NE(nist_p384 = ECGroup_fromName(ECCurve_NIST_P384), nullptr);
    CF_CHECK_NE(nist_p521 = ECGroup_fromName(ECCurve_NIST_P521), nullptr);

    ok = true;

end:
    if ( ok != true ) {
        printf("Cannot initialize NSS bignum submodule\n");
        abort();
    }
}

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

bool Sqr::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_sqr(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Mod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_mod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
    CF_CHECK_FALSE(bn[1].IsZero());

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    Bignum zero;
    mp_zero(zero.GetPtr());
    if ( mp_cmp(zero.GetPtr(), bn[0].GetPtr()) == 0 ) {
        goto end;
    }

    CF_CHECK_EQ(mp_exptmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_gcd(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool ExtGCD_X::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    Bignum gcd, y;

    Bignum zero;
    mp_zero(zero.GetPtr());
    if ( mp_cmp(zero.GetPtr(), bn[0].GetPtr()) == 0 ) {
        goto end;
    }

    CF_CHECK_EQ(mp_xgcd(bn[0].GetPtr(), bn[1].GetPtr(), gcd.GetPtr(), res.GetPtr(), y.GetPtr()), MP_OKAY);

    /* Don't return results because incorrect Bezout coefficients are returned and it will not be fixed:
     * https://bugzilla.mozilla.org/show_bug.cgi?id=1761708
     */
    //ret = true;

end:
    return ret;
}

bool ExtGCD_Y::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    Bignum gcd, x;

    Bignum zero;
    mp_zero(zero.GetPtr());
    if ( mp_cmp(zero.GetPtr(), bn[0].GetPtr()) == 0 ) {
        goto end;
    }

    CF_CHECK_EQ(mp_xgcd(bn[0].GetPtr(), bn[1].GetPtr(), gcd.GetPtr(), x.GetPtr(), res.GetPtr()), MP_OKAY);

    /* Don't return results because incorrect Bezout coefficients are returned and it will not be fixed:
     * https://bugzilla.mozilla.org/show_bug.cgi?id=1761708
     */
    //ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_addmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
    CF_CHECK_FALSE(bn[2].IsZero());

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_submod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
    CF_CHECK_FALSE(bn[2].IsZero());

    ret = true;

end:
    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_mulmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
    CF_CHECK_FALSE(bn[2].IsZero());

    ret = true;

end:
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_sqrmod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
    CF_CHECK_FALSE(bn[1].IsZero());

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    bool alt = false;
    try {
        alt = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( alt == false ) {
        if ( mp_invmod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()) != MP_OKAY ) {
            /* Inverse does not exist */
            res.Set("0");
        }
    } else {
        CF_CHECK_EQ(mp_invmod_xgcd(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
    }

    ret = true;

end:
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

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mp_cmp(bn[0].GetPtr(), bn[1].GetPtr())) );
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
    bool ret = false;

    CF_CHECK_EQ(mp_neg(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool IsEven::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;

    res.Set( std::to_string(mp_iseven(bn[0].GetPtr()) ? 1 : 0) );

    return true;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    (void)res;

    res.Set( std::to_string(mp_isodd(bn[0].GetPtr()) ? 1 : 0) );

    return true;
}

bool Exp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mp_expt(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_256::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(nist_p256->meth->field_mod(bn[0].GetPtr(), res.GetPtr(), nist_p256->meth), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_384::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(nist_p384->meth->field_mod(bn[0].GetPtr(), res.GetPtr(), nist_p384->meth), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_521::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(nist_p521->meth->field_mod(bn[0].GetPtr(), res.GetPtr(), nist_p521->meth), MP_OKAY);

    ret = true;

end:
    return ret;
}

} /* namespace NSS_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
