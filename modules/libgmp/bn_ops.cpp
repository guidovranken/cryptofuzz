#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

#define GET_WHICH() uint8_t which = 0; try { which = ds.Get<uint8_t>(); } catch ( ... ) { }

namespace cryptofuzz {
namespace module {
namespace libgmp_bignum {

bool Add::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            /* noret */ mpz_add(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_add_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool Sub::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            /* noret */ mpz_sub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_sub_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        case    2:
            {
                const auto bn0 = bn[0].GetUnsignedLong();
                CF_CHECK_NE(bn0, std::nullopt);

                /* noret */ mpz_ui_sub(res.GetPtr(), *bn0, bn[1].GetPtr());
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool Mul::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            /* noret */ mpz_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_mul_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        case    2:
            {
                const auto bn1 = bn[1].GetSignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_mul_si(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool Div::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

            /* noret */ mpz_div(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_div_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        case    2:
            {
                CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

                CF_CHECK_NE(mpz_divisible_p(bn[0].GetPtr(), bn[1].GetPtr()), 0);

                /* noret */ mpz_divexact(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            }
            break;
        case    3:
            {
                CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                CF_CHECK_NE(mpz_divisible_ui_p(bn[0].GetPtr(), *bn1), 0);

                /* noret */ mpz_divexact_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    switch ( which ) {
        case    0:
            /* "Negative exp is supported if the inverse base-1 mod mod exists.
             *  If an inverse doesn’t exist then a divide by zero is raised."
             */
            CF_CHECK_GTE(mpz_sgn(bn[1].GetPtr()), 0);

            /* noret */ mpz_powm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
            break;
        case    1:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_powm_ui(res.GetPtr(), bn[0].GetPtr(), *bn1, bn[2].GetPtr());
            }
            break;
        case    2:
            {
                CF_CHECK_GTE(mpz_sgn(bn[1].GetPtr()), 0);

                /* "It is required that exp > 0 and that mod is odd." */
                CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 1);

                const auto ptr = bn[2].GetPtr();
                CF_CHECK_EQ(mpz_odd_p(ptr), 1);

                /* noret */ mpz_powm_sec(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

enum GCDType : uint8_t {
    GCD = 0,
    ExtGCD_X = 1,
    ExtGCD_Y = 2,
};

static void GCD_ExtGCD_SetResult(mpz_ptr res, const mpz_ptr X, const mpz_ptr Y, const GCDType type) {
    if ( type == GCDType::GCD ) {
        /* do nothing */
    } else if ( type == GCDType::ExtGCD_X ) {
        /* noret */ mpz_set(res, X);
    } else if ( type == GCDType::ExtGCD_Y ) {
        /* noret */ mpz_set(res, Y);
    } else {
        CF_UNREACHABLE();
    }
}

static bool GCD_ExtGCD(Datasource& ds, Bignum& res, BignumCluster& bn, const GCDType type) {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            CF_CHECK_EQ(type, GCDType::GCD);
            /* noret */ mpz_gcd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                CF_CHECK_EQ(type, GCDType::GCD);

                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* ignore ret */ mpz_gcd_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        case    2:
            {
                Bignum t1, t2;

                /* noret */ mpz_gcdext(res.GetPtr(), t1.GetPtr(), t2.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
                CF_NORET(GCD_ExtGCD_SetResult(res.GetPtr(), t1.GetPtr(), t2.GetPtr(), type));
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    return GCD_ExtGCD(ds, res, bn, GCDType::GCD);
}

bool ExtGCD_X::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    return GCD_ExtGCD(ds, res, bn, GCDType::ExtGCD_X);
}

bool ExtGCD_Y::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    return GCD_ExtGCD(ds, res, bn, GCDType::ExtGCD_Y);
}

bool Jacobi::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    GET_WHICH();
    switch ( which ) {
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
        case    2:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);
                res.Set( std::to_string(mpz_kronecker_ui(bn[0].GetPtr(), *bn1)) );
            }
            return true;
        default:
            return false;
    }

end:
    return false;
}

bool Cmp::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    int cmp;

    GET_WHICH();
    switch ( which ) {
        case    0:
            cmp = mpz_cmp(bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                const auto bn1 = bn[1].GetSignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                cmp = mpz_cmp_si(bn[0].GetPtr(), *bn1);
            }
            break;
        case    2:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                cmp = mpz_cmp_ui(bn[0].GetPtr(), *bn1);
            }
            break;
        default:
            goto end;
    }

    if ( cmp < 0 ) {
        res.Set("-1");
    } else if ( cmp > 0 ) {
        res.Set("1");
    } else {
        res.Set("0");
    }

    ret = true;

end:
    return ret;
}

bool LCM::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            /* noret */ mpz_lcm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_lcm_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool Xor::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ mpz_xor(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool And::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ mpz_and(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool Abs::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ mpz_abs(res.GetPtr(), bn[0].GetPtr());

    return true;
}

bool Neg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ mpz_neg(res.GetPtr(), bn[0].GetPtr());

    return true;
}

bool Sqrt::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;
    (void)ds;

    CF_CHECK_GTE(mpz_sgn(bn[0].GetPtr()), 0);

    /* noret */ mpz_sqrt(res.GetPtr(), bn[0].GetPtr());
    ret = true;

end:
    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ mpz_pow_ui(res.GetPtr(), bn[0].GetPtr(), 2);

    return true;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    int cmp;

    GET_WHICH();
    switch ( which ) {
        case    0:
            cmp = mpz_cmpabs(bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                cmp = mpz_cmpabs_ui(bn[0].GetPtr(), *bn1);
            }
            break;
        default:
            goto end;
    }

    if ( cmp < 0 ) {
        res.Set("-1");
    } else if ( cmp > 0 ) {
        res.Set("1");
    } else {
        res.Set("0");
    }

    ret = true;

end:
    return ret;
}

bool IsZero::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(mpz_sgn(bn[0].GetPtr()) == 0 ? 1 : 0) );

    return true;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(mpz_sgn(bn[0].GetPtr()) < 0 ? 1 : 0) );

    return true;
}

bool AddMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    /* noret */ mpz_add(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    /* noret */ mpz_sub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[2].GetPtr(), 0), 0);

    /* noret */ mpz_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

    /* noret */ mpz_pow_ui(res.GetPtr(), bn[0].GetPtr(), 2);
    /* noret */ mpz_mod(res.GetPtr(), res.GetPtr(), bn[1].GetPtr());

    ret = true;

end:
    return ret;
}

bool Mod_NIST_192::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    Bignum p192;
    p192.Set("6277101735386680763835789423207666416083908700390324961279");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p192.GetPtr());

    return true;
}

bool Mod_NIST_224::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    Bignum p224;
    p224.Set("26959946667150639794667015087019630673557916260026308143510066298881");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p224.GetPtr());

    return true;
}

bool Mod_NIST_256::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    Bignum p256;
    p256.Set("115792089210356248762697446949407573530086143415290314195533631308867097853951");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p256.GetPtr());

    return true;
}

bool Mod_NIST_384::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    Bignum p384;
    p384.Set("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p384.GetPtr());

    return true;
}

bool Mod_NIST_521::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    Bignum p521;
    p521.Set("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");

    /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), p521.GetPtr());

    return true;
}

bool SetBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto position_sl = bn[1].GetSignedLong();
    CF_CHECK_NE(position_sl, std::nullopt);
    CF_CHECK_GTE(mpz_sgn(bn[0].GetPtr()), 0);
    CF_CHECK_GTE(mpz_sgn(bn[1].GetPtr()), 0);

    /* noret */ mpz_setbit(bn.GetDestPtr(0), *position_sl);
    /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());

    ret = true;

end:
    return ret;
}

bool ClearBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto position_sl = bn[1].GetSignedLong();
    CF_CHECK_NE(position_sl, std::nullopt);
    CF_CHECK_GTE(mpz_sgn(bn[0].GetPtr()), 0);

    /* noret */ mpz_clrbit(bn.GetDestPtr(0), *position_sl);
    /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto position_sl = bn[1].GetSignedLong();
    CF_CHECK_NE(position_sl, std::nullopt);

    res.Set( std::to_string(mpz_tstbit(bn[0].GetPtr(), *position_sl)) );

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    /* "The behaviour of this function is undefined when op2 is zero." */
    CF_CHECK_NE(mpz_sgn(bn[1].GetPtr()), 0);

    if ( mpz_invert(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()) == 0 ) {
        /* Modular inverse does not exist */
        res.Set("0");
    }

    ret = true;

end:
    return ret;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* "These macros evaluate their argument more than once." */
    const auto ptr = bn[0].GetPtr();
    res.Set( std::to_string(mpz_odd_p(ptr)) );

    return true;
}

bool IsEven::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* "These macros evaluate their argument more than once." */
    const auto ptr = bn[0].GetPtr();
    res.Set( std::to_string(mpz_even_p(ptr)) );

    return true;
}

bool IsPow2::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    if ( mpz_popcount(bn[0].GetPtr()) == 1 ) {
        res.Set("1");
    } else {
        res.Set("0");
    }

    return true;
}

bool NumLSZeroBits::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    auto numBits = mpz_scan1(bn[0].GetPtr(), 0);
    if ( numBits == (mp_bitcnt_t)-1 ) {
        numBits = 0;
    }
    res.Set( std::to_string(numBits) );

    return true;
}

bool Factorial::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto bn0 = bn[0].GetUnsignedLong();
    CF_CHECK_NE(bn0, std::nullopt);
    CF_CHECK_LTE(*bn0, 1500);

    CF_NORET(mpz_fac_ui(res.GetPtr(), *bn0));

    ret = true;

end:
    return ret;
}

bool Cbrt::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* ignore ret */ mpz_root(res.GetPtr(), bn[0].GetPtr(), 3);

    return true;
}

bool SqrtRem::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;
    (void)ds;

    CF_CHECK_GTE(mpz_sgn(bn[0].GetPtr()), 0);

    /* noret */ mpz_sqrtrem(bn[1].GetPtr(), res.GetPtr(), bn[0].GetPtr());
    ret = true;

end:
    return ret;
}

bool CbrtRem::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ mpz_rootrem(bn[1].GetPtr(), res.GetPtr(), bn[0].GetPtr(), 3);

    return true;
}

bool Nthrt::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto bn1 = bn[1].GetUnsignedLong();
    CF_CHECK_NE(bn1, std::nullopt);
    CF_CHECK_NE(*bn1, 0);
    CF_CHECK_GTE(mpz_sgn(bn[0].GetPtr()), 0);

    /* noret */ mpz_root(res.GetPtr(), bn[0].GetPtr(), *bn1);

    ret = true;
end:
    return ret;
}

bool NthrtRem::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto bn1 = bn[1].GetUnsignedLong();
    CF_CHECK_NE(bn1, std::nullopt);
    CF_CHECK_NE(*bn1, 0);
    CF_CHECK_GTE(mpz_sgn(bn[0].GetPtr()), 0);

    /* noret */ mpz_rootrem(bn[1].GetPtr(), res.GetPtr(), bn[0].GetPtr(), *bn1);

    ret = true;
end:
    return ret;
}

bool IsSquare::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set(
            mpz_perfect_square_p(bn[0].GetPtr()) == 0 ? std::string("0") : std::string("1")
    );

    return true;
}

bool Exp::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            {
                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_pow_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        case    1:
            {
                const auto bn0 = bn[0].GetUnsignedLong();
                CF_CHECK_NE(bn0, std::nullopt);

                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* noret */ mpz_ui_pow_ui(res.GetPtr(), *bn0, *bn1);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool Or::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ mpz_ior(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool AddMul::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());
            /* noret */ mpz_addmul(res.GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
            break;
        case    1:
            {
                const auto bn2 = bn[2].GetUnsignedLong();
                CF_CHECK_NE(bn2, std::nullopt);

                /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());
                /* noret */ mpz_addmul_ui(res.GetPtr(), bn[1].GetPtr(), *bn2);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool SubMul::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());
            /* noret */ mpz_submul(res.GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
            break;
        case    1:
            {
                const auto bn2 = bn[2].GetUnsignedLong();
                CF_CHECK_NE(bn2, std::nullopt);

                /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());
                /* noret */ mpz_submul_ui(res.GetPtr(), bn[1].GetPtr(), *bn2);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool Primorial::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto bn0 = bn[0].GetUnsignedLong();
    CF_CHECK_NE(bn0, std::nullopt);
    CF_CHECK_LTE(*bn0, 10000);

    /* noret */ mpz_primorial_ui(res.GetPtr(), *bn0);

    ret = true;

end:
    return ret;
}

bool Lucas::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto bn0 = bn[0].GetUnsignedLong();
    CF_CHECK_NE(bn0, std::nullopt);
    CF_CHECK_LTE(*bn0, 10000);

    /* noret */ mpz_lucnum_ui(res.GetPtr(), *bn0);

    ret = true;

end:
    return ret;
}

bool Fibonacci::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    const auto bn0 = bn[0].GetUnsignedLong();
    CF_CHECK_NE(bn0, std::nullopt);
    CF_CHECK_LTE(*bn0, 10000);

    /* noret */ mpz_fac_ui(res.GetPtr(), *bn0);

    ret = true;

end:
    return ret;
}

bool Set::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            /* noret */ mpz_set(res.GetPtr(), bn[0].GetPtr());
            break;
        case    1:
            {
                const auto bn0 = bn[0].GetUnsignedLong();
                CF_CHECK_NE(bn0, std::nullopt);

                /* noret */ mpz_init_set_ui(res.GetPtr(), *bn0);
            }
            break;
        case    2:
            {
                const auto bn0 = bn[0].GetSignedLong();
                CF_CHECK_NE(bn0, std::nullopt);

                /* noret */ mpz_init_set_si(res.GetPtr(), *bn0);
            }
            break;
        case    3:
            /* noret */ mpz_swap(res.GetPtr(), bn[0].GetPtr());
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool BinCoeff::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    std::optional<unsigned long int> bn0, bn1;

    GET_WHICH();

    bn0 = bn[0].GetUnsignedLong();
    CF_CHECK_NE(bn0, std::nullopt);
    CF_CHECK_LTE(*bn0, 100000);

    bn1 = bn[1].GetUnsignedLong();
    CF_CHECK_NE(bn1, std::nullopt);
    CF_CHECK_LTE(*bn1, 100000);

    switch ( which ) {
        case    0:
            /* noret */ mpz_bin_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            break;
        case    1:
            /* noret */ mpz_bin_uiui(res.GetPtr(), *bn0, *bn1);
            break;
        default:
            goto end;
    }

    ret = true;

end:
    return ret;
}

bool HamDist::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(mpz_hamdist(bn[0].GetPtr(), bn[1].GetPtr())) );

    return true;
}

bool Mod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    GET_WHICH();
    switch ( which ) {
        case    0:
            CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

            /* noret */ mpz_mod(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            break;
        case    1:
            {
                CF_CHECK_NE(mpz_cmp_ui(bn[1].GetPtr(), 0), 0);

                const auto bn1 = bn[1].GetUnsignedLong();
                CF_CHECK_NE(bn1, std::nullopt);

                /* ignore ret */ mpz_mod_ui(res.GetPtr(), bn[0].GetPtr(), *bn1);
            }
            break;
        default:
            return false;
    }

    ret = true;

end:
    return ret;
}

bool IsPower::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set(
            mpz_perfect_power_p(bn[0].GetPtr()) == 0 ? std::string("0") : std::string("1")
    );

    return true;
}

} /* namespace libgmp_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
