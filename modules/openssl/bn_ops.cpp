#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

/* Not included in public headers */
#if defined(CRYPTOFUZZ_BORINGSSL)
extern "C" {
    int bn_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
}
#endif

namespace cryptofuzz {
namespace module {
namespace OpenSSL_bignum {

bool Add::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_add(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;
        case    1:
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_EQ(BN_is_negative(bn[1].GetPtr()), 0);
            CF_CHECK_EQ(BN_uadd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool Sub::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_sub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;

    /* OpenSSL and LibreSSL return a positive value for BN_usub(A,B)
     * where A > B
     */
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    1:
            CF_CHECK_EQ(BN_is_negative(bn[0].GetPtr()), 0);
            CF_CHECK_EQ(BN_is_negative(bn[1].GetPtr()), 0);
            CF_CHECK_EQ(BN_usub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);
            break;
#endif
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    CF_CHECK_EQ(BN_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    1:
            /* "BN_mod() corresponds to BN_div() with dv set to NULL" */
            CF_CHECK_EQ(BN_div(nullptr, res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_exp_mont_consttime(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr(), nullptr), 1);
            break;
        case    1:
            CF_CHECK_EQ(BN_mod_exp_mont(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr(), nullptr), 1);
            break;
        case    2:
            CF_CHECK_EQ(BN_mod_exp(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    3:
#if !defined(CRYPTOFUZZ_BORINGSSL)
            CF_CHECK_EQ(BN_mod_exp_simple(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
#else
            goto end;
#endif
            break;
        default:
            goto end;
            break;

    }

    ret = true;

end:
    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_sqr(res.GetPtr(), bn[0].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_gcd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_add(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    1:
            {
                Bignum zero(ds);
                CF_CHECK_EQ(zero.New(), true);

                /* "... may be used if both a and b are non-negative and less than m" */
                CF_CHECK_GTE(BN_cmp(bn[0].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_GTE(BN_cmp(bn[1].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[1].GetPtr(), bn[2].GetPtr()), 0);
                CF_CHECK_EQ(BN_mod_add_quick(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 1);
            }
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_sub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    1:
            {
                Bignum zero(ds);
                CF_CHECK_EQ(zero.New(), true);

                /* "... may be used if both a and b are non-negative and less than m" */
                CF_CHECK_GTE(BN_cmp(bn[0].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_GTE(BN_cmp(bn[1].GetPtr(), zero.GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[0].GetPtr(), bn[2].GetPtr()), 0);
                CF_CHECK_LT(BN_cmp(bn[1].GetPtr(), bn[2].GetPtr()), 0);
                CF_CHECK_EQ(BN_mod_sub_quick(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 1);
            }
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), ctx.GetPtr()), 1);
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_mod_sqr(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_NE(BN_mod_inverse(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), nullptr);
            break;
        default:
            goto end;
            break;
    }

    ret = true;

end:
    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_cmp(bn[0].GetPtr(), bn[1].GetPtr())) );

    return true;
}

bool IsPrime::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

#if defined(CRYPTOFUZZ_BORINGSSL) || defined(CRYPTOFUZZ_LIBRESSL)
    const int ret = BN_is_prime_ex(bn[0].GetPtr(), 0, nullptr, nullptr);
    if ( ret == -1 ) {
        return false;
    }

    res.Set( std::to_string(ret) );

    return true;
#else
    (void)res;
    (void)bn;
    return false;
#endif
}

bool Sqrt::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

#if defined(CRYPTOFUZZ_BORINGSSL)
    CF_CHECK_EQ(BN_sqrt(res.GetPtr(), bn[0].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
#else
    (void)res;
    (void)bn;
    (void)ctx;

#endif
    return ret;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_negative(bn[0].GetPtr())) );

    return true;
}

bool IsEq::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

#if defined(CRYPTOFUZZ_BORINGSSL)
    res.Set( std::to_string(BN_equal_consttime(bn[0].GetPtr(), bn[1].GetPtr())) );

    return true;
#else
    (void)res;
    (void)bn;
    return false;
#endif
}

bool IsEven::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(!BN_is_odd(bn[0].GetPtr())) );

    return true;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_odd(bn[0].GetPtr())) );

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_zero(bn[0].GetPtr())) );

    return true;
}

bool IsOne::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;

    res.Set( std::to_string(BN_is_one(bn[0].GetPtr())) );

    return true;
}

bool Jacobi::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

#if !defined(CRYPTOFUZZ_BORINGSSL)
    const int jacobi = BN_kronecker(bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr());
#else
    const int jacobi = bn_jacobi(bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr());
#endif

    CF_CHECK_NE(jacobi, -2);

    res.Set( std::to_string(jacobi) );

    ret = true;
end:

    return ret;
}

#if !defined(CRYPTOFUZZ_BORINGSSL)
bool Mod_NIST_192::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_192(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_224::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_224(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_256::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_256(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_384::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_384(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Mod_NIST_521::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_nist_mod_521(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}
#endif

} /* namespace OpenSSL_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
