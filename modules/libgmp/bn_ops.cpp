#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

namespace cryptofuzz {
namespace module {
namespace libgmp_bignum {

bool Add::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_add(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    return true;
}

bool Sub::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_sub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    return true;
}

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    return true;
}

bool Div::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

    /* noret */ mpz_div(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    /* noret */ mpz_powm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_gcd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool Jacobi::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            res.Set( std::to_string(mpz_jacobi(bn[0].GetPtr(), bn[1].GetPtr())) );
            return true;
        case    1:
            {
                const auto bn1 = bn[1].GetSignedLong();
                CF_CHECK_NE(bn1, std::nullopt);
                res.Set( std::to_string(mpz_kronecker_si(bn[0].GetPtr(), *bn1)) );
            }
            return true;
        default:
            return false;
    }

end:
    return false;
}

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    const int cmp = mpz_cmp(bn[0].GetPtr(), bn[1].GetPtr());

    if ( cmp < 0 ) {
        res.Set("-1");
    } else if ( cmp > 0 ) {
        res.Set("1");
    } else {
        res.Set("0");
    }

    return true;
}

bool LCM::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_lcm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool Xor::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_xor(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool And::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_and(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool Abs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_abs(res.GetPtr(), bn[0].GetPtr());

    return true;
}

bool Neg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_neg(res.GetPtr(), bn[0].GetPtr());

    return true;
}

bool Sqrt::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_sqrt(res.GetPtr(), bn[0].GetPtr());

    return true;
}

bool Sqr::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_pow_ui(res.GetPtr(), bn[0].GetPtr(), 2);

    return true;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    const int cmp = mpz_cmpabs(bn[0].GetPtr(), bn[1].GetPtr());

    if ( cmp < 0 ) {
        res.Set("-1");
    } else if ( cmp > 0 ) {
        res.Set("1");
    } else {
        res.Set("0");
    }

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mpz_sgn(bn[0].GetPtr()) == 0 ? 1 : 0) );

    return true;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mpz_sgn(bn[0].GetPtr()) < 0 ? 1 : 0) );

    return true;
}

bool AddMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    /* noret */ mpz_add(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    /* noret */ mpz_sub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    /* noret */ mpz_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

    /* noret */ mpz_pow_ui(res.GetPtr(), bn[0].GetPtr(), 2);
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[1].GetPtr());

    ret = true;

end:
    return ret;
}

bool Mod_NIST_192::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    Bignum p192;
    p192.Set("6277101735386680763835789423207666416083908700390324961279");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p192.GetPtr());

    return true;
}

bool Mod_NIST_224::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    Bignum p224;
    p224.Set("26959946667150639794667015087019630673557916260026308143510066298881");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p224.GetPtr());

    return true;
}

bool Mod_NIST_256::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    Bignum p256;
    p256.Set("115792089210356248762697446949407573530086143415290314195533631308867097853951");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p256.GetPtr());

    return true;
}

bool Mod_NIST_384::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    Bignum p384;
    p384.Set("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p384.GetPtr());

    return true;
}

bool Mod_NIST_521::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    Bignum p521;
    p521.Set("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p521.GetPtr());

    return true;
}

bool SetBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    const auto position_sl = bn[1].GetSignedLong();
    CF_CHECK_NE(position_sl, std::nullopt);

    /* noret */ mpz_setbit(bn[0].GetPtr(), *position_sl);
    /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());

    ret = true;

end:
    return ret;
}

bool ClearBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    const auto position_sl = bn[1].GetSignedLong();
    CF_CHECK_NE(position_sl, std::nullopt);

    /* noret */ mpz_clrbit(bn[0].GetPtr(), *position_sl);
    /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    const auto position_sl = bn[1].GetSignedLong();
    CF_CHECK_NE(position_sl, std::nullopt);

    res.Set( std::to_string(mpz_tstbit(bn[0].GetPtr(), *position_sl)) );

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    /* "The behaviour of this function is undefined when op2 is zero." */
    CF_CHECK_NE(mpz_sgn(bn[1].GetPtr()), 0);

    CF_CHECK_NE(mpz_invert(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* "These macros evaluate their argument more than once." */
    const auto ptr = bn[0].GetPtr();
    res.Set( std::to_string(mpz_odd_p(ptr)) );

    return true;
}

bool IsEven::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* "These macros evaluate their argument more than once." */
    const auto ptr = bn[0].GetPtr();
    res.Set( std::to_string(mpz_even_p(ptr)) );

    return true;
}

bool IsPow2::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    if ( mpz_popcount(bn[0].GetPtr()) == 1 ) {
        res.Set("1");
    } else {
        res.Set("0");
    }

    return true;
}

} /* namespace libgmp_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
