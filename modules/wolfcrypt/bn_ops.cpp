#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

#define GET_OPTIONAL_BN() (ds.Get<bool>() ? bn.GetDestPtr(3) : nullptr)

namespace cryptofuzz {
namespace module {

namespace wolfCrypt_detail {
    WC_RNG* GetRNG(void);
}

namespace wolfCrypt_bignum {

namespace wolfCrypt_bignum_detail {
    static int compare(Bignum& A, Bignum& B) {
        return mp_cmp(A.GetPtr(), B.GetPtr());
    }
}

bool Add::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_add(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
            ret = true;
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                CF_CHECK_EQ(mp_add_d(bn[0].GetPtr(), *op, res.GetPtr()), MP_OKAY);
                ret = true;
            }
            break;
    }

end:
    return ret;
}

bool Sub::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    /* SP math cannot represent negative numbers, so ensure the result
     * of the subtracton is always >= 0.
     *
     * Still run the subtraction operation to see if this can cause
     * memory errors, but don't return the result.
     */
    bool negative = false;
    if ( wolfCrypt_bignum_detail::compare(bn[0], bn[1]) == MP_LT) {
        negative = true;
    }
#endif

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_sub(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
            ret = true;
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                CF_CHECK_EQ(mp_sub_d(bn[0].GetPtr(), *op, res.GetPtr()), MP_OKAY);
                ret = true;
            }
            break;
    }

end:
#if defined(WOLFSSL_SP_MATH)
    if ( negative == true ) {
        return false;
    }
#endif
    return ret;
}

bool Mul::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_mul(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
            ret = true;
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                CF_CHECK_EQ(mp_mul_d(bn[0].GetPtr(), *op, res.GetPtr()), MP_OKAY);
                ret = true;
            }
            break;
#if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
        case    2:
            CF_CHECK_EQ(mp_cmp_d(bn[1].GetPtr(), 2), MP_EQ);
            CF_CHECK_EQ(mp_mul_2(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
            ret = true;
            break;
#endif
    }

end:
    return ret;
}

bool Div::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_div(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr(), GET_OPTIONAL_BN()), MP_OKAY);
            break;
        case    1:
            CF_CHECK_EQ(mp_cmp_d(bn[1].GetPtr(), 2), MP_EQ);
            CF_CHECK_EQ(mp_div_2(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
#if !defined(USE_FAST_MATH)
        case    2:
            CF_CHECK_EQ(mp_cmp_d(bn[1].GetPtr(), 3), MP_EQ);
            CF_CHECK_EQ(mp_div_3(bn[0].GetPtr(), res.GetPtr(), nullptr), MP_OKAY);
            break;
#endif
        default:
            goto end;
    }

    ret = true;

end:
#endif
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_exptmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        case    1:
            CF_CHECK_EQ(mp_exptmod_nct(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
#if !defined(WOLFSSL_SP_MATH)
        case    2:
            CF_CHECK_EQ(mp_exptmod_ex(bn[0].GetPtr(), bn[1].GetPtr(), bn[1].GetPtr()->used, bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
#endif
#if defined(WOLFSSL_SP_MATH)
        case    3:
            CF_CHECK_EQ(sp_ModExp_1024(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        case    4:
            CF_CHECK_EQ(sp_ModExp_1536(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        case    5:
            CF_CHECK_EQ(sp_ModExp_2048(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        case    6:
            CF_CHECK_EQ(sp_ModExp_3072(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        case    7:
            CF_CHECK_EQ(sp_ModExp_4096(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
#endif
        default:
            goto end;
    }

#if defined(WOLFSSL_SP_MATH)
    ret = true;
#else
    if (
            !mp_iszero(bn[1].GetPtr()) &&
            !mp_isneg(bn[0].GetPtr()) &&
            !mp_isneg(bn[1].GetPtr()) &&
            !mp_isneg(bn[2].GetPtr()) ) {
            ret = true;
    }
#endif

end:
    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    CF_CHECK_EQ(mp_sqr(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
#endif
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    bool ret = false;

    CF_CHECK_EQ(mp_gcd(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_invmod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    int cmpRes = 0;
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            cmpRes = wolfCrypt_bignum_detail::compare(bn[0], bn[1]);
            break;
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                cmpRes = mp_cmp_d(bn[0].GetPtr(), *op);
            }
            break;
        default:
            goto end;
    }

    switch ( cmpRes ) {
        case    MP_GT:
            CF_CHECK_EQ( res.Set("1"), true);
            break;
        case    MP_LT:
            CF_CHECK_EQ( res.Set("-1"), true);
            break;
        case    MP_EQ:
            CF_CHECK_EQ( res.Set("0"), true);
            break;
        default:
            /* Invalid return value */
            abort();
    }

    ret = true;

end:
    return ret;
}

bool Abs::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_abs(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Neg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(mp_sub(res.GetPtr(), bn[0].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
#endif

    return ret;
}

bool RShift::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    std::optional<uint64_t> _numBits;
    int numBits;

    CF_CHECK_NE(_numBits = bn[1].AsUint64(), std::nullopt);
    CF_CHECK_LTE(_numBits, 2147483647);

    numBits = *_numBits;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_copy(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
            /* noret */ mp_rshb(res.GetPtr(), numBits);
            ret = true;
            break;
#if !defined(WOLFSSL_SP_MATH)
        case    1:
            CF_CHECK_EQ(mp_div_2d(bn[0].GetPtr(), numBits, res.GetPtr(), GET_OPTIONAL_BN()), MP_OKAY);
            ret = true;
            break;
#endif
    }

end:

    return ret;
}

bool LShift1::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    CF_CHECK_EQ(mp_mul_2d(bn[0].GetPtr(), 1, res.GetPtr()), MP_OKAY);

    ret = true;

end:
#endif

    return ret;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    CF_CHECK_EQ( res.Set( std::to_string(mp_isneg(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:
#endif
    return ret;
}

bool IsEq::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const bool isEq = mp_cmp(bn[0].GetPtr(), bn[1].GetPtr()) == MP_EQ;
    CF_CHECK_EQ( res.Set( std::to_string(isEq ? 1 : 0) ), true);

    ret = true;

end:
    return ret;
}

bool IsZero::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ( res.Set( std::to_string(mp_iszero(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:
    return ret;
}

bool IsOne::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ( res.Set( std::to_string(mp_isone(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:
    return ret;
}

bool MulMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_mulmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_addmod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        case    1:
            CF_CHECK_EQ(mp_cmp(bn[0].GetPtr(), bn[1].GetPtr()), MP_LT);
            CF_CHECK_EQ(mp_cmp(bn[1].GetPtr(), bn[2].GetPtr()), MP_LT);
            CF_CHECK_EQ(mp_addmod_ct(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        default:
            goto end;
    }

    ret = true;

end:
#endif
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_submod(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        case    1:
            CF_CHECK_EQ(mp_cmp(bn[0].GetPtr(), bn[1].GetPtr()), MP_LT);
            CF_CHECK_EQ(mp_cmp(bn[1].GetPtr(), bn[2].GetPtr()), MP_LT);
            CF_CHECK_EQ(mp_submod_ct(bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
        default:
            goto end;
    }

    ret = true;

end:
#endif
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    CF_CHECK_EQ(mp_sqrmod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
#endif
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

#if defined(WOLFSSL_SP_MATH)
    (void)res;
    (void)bn;
#else
    std::optional<uint64_t> _bitPos;
    mp_digit bitPos;
    int isBitSet;

    CF_CHECK_NE(_bitPos = bn[1].AsUint64(), std::nullopt);

    bitPos = *_bitPos;
    /* Ensure no truncation has occurred */
    CF_CHECK_EQ(bitPos, *_bitPos);

    CF_CHECK_GTE(isBitSet = mp_is_bit_set(bn[0].GetPtr(), bitPos), 0);
    CF_CHECK_EQ( res.Set(isBitSet ? "1" : "0"), true);

    ret = true;

end:
#endif
    return ret;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    (void)res;
    (void)bn;

    /* TODO */

    bool ret = false;

    return ret;
}

bool SetBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    std::optional<uint64_t> _bitPos;
    mp_digit bitPos;

    CF_CHECK_NE(_bitPos = bn[1].AsUint64(), std::nullopt);

    bitPos = *_bitPos;
    /* Ensure no truncation has occurred */
    CF_CHECK_EQ(bitPos, *_bitPos);

    CF_CHECK_EQ(mp_copy(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
    CF_CHECK_EQ(mp_set_bit(res.GetPtr(), bitPos), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool LCM::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_lcm(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Mod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_mod(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
            break;
#if !defined(WOLFSSL_SP_MATH)
        case    1:
            {
                const auto op = bn[1].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                mp_digit modResult;
                CF_CHECK_EQ(mp_mod_d(bn[0].GetPtr(), *op, &modResult), MP_OKAY);
                CF_CHECK_EQ(res.Set(std::to_string(modResult)), true);
            }
            break;
        case    2:
            {
                /* bn[0] *= 2 */
                CF_CHECK_EQ(mp_mul_d(bn[0].GetPtr(), 2, bn.GetDestPtr(0)), MP_OKAY);

                CF_CHECK_EQ(mp_cmp(bn[0].GetPtr(), bn[1].GetPtr()), MP_LT);
                CF_CHECK_EQ(mp_div_2_mod_ct(bn[0].GetPtr(), bn[1].GetPtr(), res.GetPtr()), MP_OKAY);
            }
            break;
#endif
        default:
            goto end;
    }

    ret = true;

end:
    return ret;
}

bool IsEven::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ(mp_iszero(bn[0].GetPtr()), false);

    CF_CHECK_EQ( res.Set( std::to_string(mp_iseven(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:

    return ret;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    CF_CHECK_EQ( res.Set( std::to_string(mp_isodd(bn[0].GetPtr()) ? 1 : 0) ), true);

    ret = true;

end:

    return ret;
}

bool MSB::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const int bit = mp_leading_bit(bn[0].GetPtr());

    /* Must be 0 or 1 */
    if ( bit != 0 && bit != 1 ) {
        abort();
    }

    CF_CHECK_EQ( res.Set( std::to_string(bit) ), true);

    ret = true;

end:

    return ret;
}

bool NumBits::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const auto numBits = mp_count_bits(bn[0].GetPtr());

    /* Basic sanity check */
    if ( numBits < 0 ) {
        abort();
    }

    CF_CHECK_EQ( res.Set( std::to_string(numBits) ), true);

    ret = true;

end:
    return ret;
}

bool Set::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mp_copy(bn[0].GetPtr(), res.GetPtr()), MP_OKAY);
            ret = true;
            break;
        case    1:
            {
                const auto op = bn[0].AsUnsigned<mp_digit>();
                CF_CHECK_NE(op, std::nullopt);
                CF_CHECK_EQ(mp_set(res.GetPtr(), *op), MP_OKAY);
                ret = true;
            }
            break;
        case    2:
            {
                /* mp_exch only returns a value when wolfCrypt is compiled
                 * with fast math; it does not return a value when compiled
                 * with --disable-fastmath or SP math.
                 */
#if defined(USE_FAST_MATH)
                CF_CHECK_EQ(mp_exch(res.GetPtr(), bn[0].GetPtr()), MP_OKAY);
#else
                /* noret */ mp_exch(res.GetPtr(), bn[0].GetPtr());
#endif
                ret = true;
            }
            break;
        case    3:
            {
                const auto op = bn[0].AsUnsigned<unsigned long>();
                CF_CHECK_NE(op, std::nullopt);
                CF_CHECK_EQ(mp_set_int(res.GetPtr(), *op), MP_OKAY);
                ret = true;
            }
            break;
    }

end:
    return ret;
}

#if defined(HAVE_COMP_KEY) && !defined(WOLFSSL_SP_MATH)
  #define HAVE_MP_JACOBI 1
#endif

#if defined(HAVE_MP_JACOBI)
extern "C" {
int mp_jacobi(mp_int* a, mp_int* n, int* c);
}
#endif

bool Jacobi::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    (void)ds;

#if !defined(HAVE_MP_JACOBI)
    (void)res;
    (void)bn;
#else
    if ( mp_isodd(bn[1].GetPtr()) ) {
        int jacobi;
        CF_CHECK_EQ(mp_jacobi(bn[0].GetPtr(), bn[1].GetPtr(), &jacobi), MP_OKAY);

        switch ( jacobi ) {
            case    1:
                CF_CHECK_EQ( res.Set("1"), true);
                break;
            case    -1:
                CF_CHECK_EQ( res.Set("-1"), true);
                break;
            case    0:
                CF_CHECK_EQ( res.Set("0"), true);
                break;
            default:
                printf("Error: mp_jacobi returned %d\n", jacobi);
                /* Invalid return value */
                abort();
        }

        ret = true;
    }

end:
#endif

    return ret;
}

bool Exp2::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const auto exponent = bn[0].AsUnsigned<unsigned int>();
    CF_CHECK_NE(exponent, std::nullopt);
#if defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
    CF_CHECK_LT(*exponent / DIGIT_BIT, FP_SIZE);
#endif
    CF_CHECK_EQ(mp_2expt(res.GetPtr(), *exponent), MP_OKAY);

    ret = true;

end:

    return ret;
}

bool NumLSZeroBits::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

#if defined(WOLFSSL_SP_MATH) || (defined(USE_FAST_MATH) && !defined(HAVE_COMP_KEY))
    (void)res;
    (void)bn;
#else
    const auto numBits = mp_cnt_lsb(bn[0].GetPtr());

    /* Basic sanity check */
    if ( numBits < 0 ) {
        abort();
    }

    CF_CHECK_EQ( res.Set( std::to_string(numBits) ), true);

    ret = true;

end:
#endif

    return ret;
}

bool MulAdd::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    bool ret = false;

    std::optional<std::string> mulRes, toAdd;

    auto mul = std::make_unique<Mul>();
    auto add = std::make_unique<Add>();

    CF_CHECK_NE(toAdd = bn[2].ToDecString(), std::nullopt);

    CF_CHECK_EQ(mul->Run(ds, res, bn), true);

    CF_CHECK_NE(mulRes = res.ToDecString(), std::nullopt);
    CF_CHECK_EQ(bn.Set(0, *mulRes), true);

    CF_CHECK_EQ(bn.Set(1, *toAdd), true);
    CF_CHECK_EQ(add->Run(ds, res, bn), true);

    ret = true;

end:
    return ret;
}

bool CondSet::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    const int doCopy = mp_iszero(bn[1].GetPtr()) ? 0 : 1;
    CF_CHECK_EQ(mp_cond_copy(bn[0].GetPtr(), doCopy, res.GetPtr()), MP_OKAY);

    ret = true;

end:
    return ret;
}

bool Rand::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    (void)bn;

    bool ret = false;

    switch ( ds.Get<uint8_t>() ) {
        case    0:
            {
                const auto len = ds.Get<uint16_t>() % 512;
                CF_CHECK_EQ(mp_rand(res.GetPtr(), len, wolfCrypt_detail::GetRNG()), MP_OKAY);
                ret = true;
            }
            break;
        case    1:
            {
                const auto len = ds.Get<uint16_t>() % 512;
                CF_CHECK_EQ(mp_rand_prime(res.GetPtr(), len, wolfCrypt_detail::GetRNG(), nullptr), MP_OKAY);
                ret = true;
            }
            break;
    }

end:
    return ret;
}

} /* namespace wolfCrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
