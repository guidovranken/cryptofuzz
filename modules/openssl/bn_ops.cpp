#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

/* Not included in public headers */
#if defined(CRYPTOFUZZ_BORINGSSL)
extern "C" {
    int bn_jacobi(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
    int bn_div_consttime(BIGNUM *quotient, BIGNUM *remainder, const BIGNUM *numerator, const BIGNUM *divisor, BN_CTX *ctx);
    int bn_lcm_consttime(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
    uint16_t bn_mod_u16_consttime(const BIGNUM *bn, uint16_t d);
}
#endif

/* Not included in public headers */
#if defined(CRYPTOFUZZ_LIBRESSL)
extern "C" {
    int BN_gcd_ct(BIGNUM *r, const BIGNUM *in_a, const BIGNUM *in_b, BN_CTX *ctx);
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
        case    2:
            {
                std::optional<uint64_t> v64;

                /* Convert bn[1] to uint64_t if possible */
                CF_CHECK_NE(v64 = bn[1].AsUint64(), std::nullopt);

                /* Cannot divide by 0 */
                CF_CHECK_NE(*v64, 0);

                /* Try to convert the uint64_t to BN_ULONG */
                BN_ULONG vul;
                CF_CHECK_EQ(vul = *v64, *v64);

                /* bn[0] += vul (which is bn[1]) */
                CF_CHECK_EQ(BN_add_word(bn[0].GetPtr(), vul), 1);

                CF_CHECK_EQ(res.Set(bn[0]), true);
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
        case    2:
            {
                std::optional<uint64_t> v64;

                /* Convert bn[1] to uint64_t if possible */
                CF_CHECK_NE(v64 = bn[1].AsUint64(), std::nullopt);

                /* Cannot divide by 0 */
                CF_CHECK_NE(*v64, 0);

                /* Try to convert the uint64_t to BN_ULONG */
                BN_ULONG vul;
                CF_CHECK_EQ(vul = *v64, *v64);

                /* bn[0] -= vul (which is bn[1]) */
                CF_CHECK_EQ(BN_sub_word(bn[0].GetPtr(), vul), 1);

                CF_CHECK_EQ(res.Set(bn[0]), true);
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

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            {
                CF_CHECK_EQ(BN_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            }
            break;
        case    1:
            {
                std::optional<uint64_t> v64;

                /* Convert bn[1] to uint64_t if possible */
                CF_CHECK_NE(v64 = bn[1].AsUint64(), std::nullopt);

                /* Cannot divide by 0 */
                CF_CHECK_NE(*v64, 0);

                /* Try to convert the uint64_t to BN_ULONG */
                BN_ULONG vul;
                CF_CHECK_EQ(vul = *v64, *v64);

                /* bn[0] *= vul (which is bn[1]) */
                CF_CHECK_EQ(BN_mul_word(bn[0].GetPtr(), vul), 1);

                CF_CHECK_EQ(res.Set(bn[0]), true);
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
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    2:
            CF_CHECK_EQ(bn_div_consttime(nullptr, res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
        case    3:
            CF_CHECK_EQ(BN_is_pow2(bn[1].GetPtr()), 1);
            CF_CHECK_EQ(BN_mod_pow2(res.GetPtr(), bn[0].GetPtr(), BN_num_bits(bn[1].GetPtr()) - 1), 1);
            break;
        case    4:
            {
                std::optional<uint64_t> v64;

                /* Convert bn[1] to uint64_t if possible */
                CF_CHECK_NE(v64 = bn[1].AsUint64(), std::nullopt);

                /* Try to convert the uint64_t to uint16_t */
                uint16_t v16;
                CF_CHECK_EQ(v16 = *v64, *v64);

                CF_CHECK_GT(v16, 1);

                /* This condition is imposed by bn_mod_u16_consttime, which
                 * triggers an assert failure otherwise
                 */
                CF_CHECK_LTE(BN_num_bits_word(v16 - 1), 16);

                /* ret = bn[0] MOD v16 (which is bn[1]) */
                const auto ret = bn_mod_u16_consttime(bn[0].GetPtr(), v16);
                res.SetUint32(ret);
            }
            break;
#endif
        case    5:
            {
                std::optional<uint64_t> v64;

                /* Convert bn[1] to uint64_t if possible */
                CF_CHECK_NE(v64 = bn[1].AsUint64(), std::nullopt);

                /* Cannot mod 0 */
                CF_CHECK_NE(*v64, 0);

                /* Try to convert the uint64_t to BN_ULONG */
                BN_ULONG vul;
                CF_CHECK_EQ(vul = *v64, *v64);

                /* ret = bn[0] MOD vul (which is bn[1]) */
                const auto ret = BN_mod_word(bn[0].GetPtr(), vul);

                /* Try to convert the BN_ULONG to uint32_t */
                uint32_t ret32;
                CF_CHECK_EQ(ret32 = ret, ret);

                res.SetUint32(ret32);
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

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_gcd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
#if defined(CRYPTOFUZZ_LIBRESSL)
        case    1:
            CF_CHECK_EQ(BN_gcd_ct(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
#endif
        default:
            goto end;
    }

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

bool Div::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(BN_div(res.GetPtr(), nullptr, bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    1:
            CF_CHECK_EQ(bn_div_consttime(res.GetPtr(), nullptr, bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);
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

bool SqrtMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    /* Disabled due to slowness of primality testing */
#if 0
    (void)ds;
    bool ret = false;

    /* Third parameter to BN_mod_sqrt must be prime */
    CF_CHECK_EQ(BN_is_prime_ex(bn[1].GetPtr(), 64, ctx.GetPtr(), nullptr), 1);
    CF_CHECK_NE(BN_mod_sqrt(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), nullptr);

    ret = true;

end:
    return ret;
#else
    (void)ds;
    (void)res;
    (void)bn;
    (void)ctx;
    return false;
#endif
}

#if defined(CRYPTOFUZZ_BORINGSSL)
bool LCM::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(bn_lcm_consttime(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}
#endif

bool Exp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(BN_exp(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx.GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Abs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn, BN_CTX& ctx) const {
    (void)ds;
    (void)ctx;
    bool ret = false;

    if ( BN_is_negative(bn[0].GetPtr()) ) {
        Bignum zero(ds);
        CF_CHECK_EQ(zero.New(), true);

        switch ( ds.Get<uint8_t>() ) {
            case    0:
                CF_CHECK_EQ(BN_sub(res.GetPtr(), zero.GetPtr(), bn[0].GetPtr()), 1);
                break;
            case    1:
                CF_CHECK_EQ(BN_sub(res.GetPtr(), bn[0].GetPtr(), bn[0].GetPtr()), 1);
                CF_CHECK_EQ(BN_sub(res.GetPtr(), res.GetPtr(), bn[0].GetPtr()), 1);
                break;
            default:
                goto end;
                break;
        }
    } else {
        CF_CHECK_NE(BN_copy(res.GetPtr(), bn[0].GetPtr()), nullptr);
    }

    ret = true;

end:
    return ret;
}

} /* namespace OpenSSL_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
