#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

#define GET_WHICH(max) uint8_t which = 0; try { which = ds.Get<uint8_t>(); which %= ((max)+1); } catch ( ... ) { }

using mpi_barrett_t = void*;

extern "C" {
void _gcry_mpi_mulpowm( gcry_mpi_t res, gcry_mpi_t *basearray, gcry_mpi_t *exparray, gcry_mpi_t mod);

mpi_barrett_t _gcry_mpi_barrett_init(gcry_mpi_t m, int copy);
void _gcry_mpi_mod_barrett (gcry_mpi_t r, gcry_mpi_t x, mpi_barrett_t ctx);
void _gcry_mpi_mul_barrett (gcry_mpi_t w, gcry_mpi_t u, gcry_mpi_t v, mpi_barrett_t ctx);
void _gcry_mpi_barrett_free(mpi_barrett_t ctx);
}

namespace cryptofuzz {
namespace module {
namespace libgcrypt_bignum {

bool Add::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    GET_WHICH(1);
    switch ( which ) {
        case    0:
            /* noret */ gcry_mpi_add(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            CF_NORET(bn.CopyResult(res));
            return true;
        case    1:
            {
                unsigned int ui;
                CF_CHECK_EQ(gcry_mpi_get_ui(&ui, bn[1].GetPtr()), 0);
                /* noret */ gcry_mpi_add_ui(bn.GetResPtr(), bn[0].GetPtr(), ui);
                CF_NORET(bn.CopyResult(res));
                return true;
            }
            break;
    }

end:
    return false;
}

bool Sub::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    GET_WHICH(1);
    switch ( which ) {
        case    0:
            /* noret */ gcry_mpi_sub(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            CF_NORET(bn.CopyResult(res));
            return true;
        case    1:
            {
                unsigned int ui;
                CF_CHECK_EQ(gcry_mpi_get_ui(&ui, bn[1].GetPtr()), 0);
                /* noret */ gcry_mpi_sub_ui(bn.GetResPtr(), bn[0].GetPtr(), ui);
                CF_NORET(bn.CopyResult(res));
                return true;
            }
            break;
    }

end:
    return false;
}

bool Mul::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    GET_WHICH(2);
    switch ( which ) {
        case    0:
            /* noret */ gcry_mpi_mul(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            CF_NORET(bn.CopyResult(res));
            return true;
        case    1:
            {
                unsigned int ui;
                CF_CHECK_EQ(gcry_mpi_get_ui(&ui, bn[1].GetPtr()), 0);
                /* noret */ gcry_mpi_mul_ui(bn.GetResPtr(), bn[0].GetPtr(), ui);
                CF_NORET(bn.CopyResult(res));
                return true;
            }
            break;
        case    2:
            {
                util::HintBignumPow2();

                /* Test if bn[1] is exponent of 2 */
                CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);

                const size_t num_bits = gcry_mpi_get_nbits(bn[1].GetPtr());
                size_t num_1_bits = 0;
                unsigned int pos = 0;
                for (size_t i = 0; i < num_bits; i++) {
                    if ( gcry_mpi_test_bit(bn[1].GetPtr(), i) ) {
                        pos = i;
                        num_1_bits++;
                        CF_CHECK_LTE(num_1_bits, 1);
                    }
                }

                gcry_mpi_mul_2exp(bn.GetResPtr(), bn[0].GetPtr(), pos);
                CF_NORET(bn.CopyResult(res));

                return true;
            }
            break;
    }

end:
    return false;
}

bool Div::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_div(bn.GetResPtr(), nullptr, bn[0].GetPtr(), bn[1].GetPtr(), 0);
    CF_NORET(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    GET_WHICH(1);

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);

    switch ( which ) {
        case    0:
            /* noret */ gcry_mpi_powm(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
            CF_NORET(bn.CopyResult(res));
            return true;
        case    1:
            {
                CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);

                gcry_mpi_t base[2] = { bn[0].GetPtr(), nullptr };
                gcry_mpi_t exp[2] = { bn[1].GetPtr(), nullptr };

                /* noret */ _gcry_mpi_mulpowm(res.GetPtr(), base, exp, bn[2].GetPtr());
            }
            return true;
    }

end:
    return false;
}

bool GCD::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[0].GetPtr(), 0), 0);
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);
    /* return value not important */ gcry_mpi_gcd(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    CF_NORET(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);
    if ( gcry_mpi_invm(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()) == 0 ) {
        /* Modular inverse does not exist */
        res.Set("0");
    } else {
        CF_NORET(bn.CopyResult(res));
    }

    ret = true;

end:
    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    GET_WHICH(1);
    switch ( which ) {
        case    0:
            {
                const auto cmpres = gcry_mpi_cmp(bn[0].GetPtr(), bn[1].GetPtr() );
                if ( cmpres == 0 ) {
                    res.Set("0");
                } else if ( cmpres < 0 ) {
                    res.Set("-1");
                } else if ( cmpres > 0 ) {
                    res.Set("1");
                }
            }
            return true;
        case    1:
            {
                unsigned int ui;
                CF_CHECK_EQ(gcry_mpi_get_ui(&ui, bn[1].GetPtr()), 0);
                const auto cmpres = gcry_mpi_cmp_ui(bn[0].GetPtr(), ui);
                if ( cmpres == 0 ) {
                    res.Set("0");
                } else if ( cmpres < 0 ) {
                    res.Set("-1");
                } else if ( cmpres > 0 ) {
                    res.Set("1");
                }
            }
            return true;
    }

end:
    return false;
}

bool Abs::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* ignore return value */ gcry_mpi_set(res.GetPtr(), bn[0].GetPtr());
    /* noret */ gcry_mpi_abs(res.GetPtr());

    return true;
}

bool Neg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ gcry_mpi_neg(bn.GetResPtr(), bn[0].GetPtr());
    CF_NORET(bn.CopyResult(res));

    return true;
}

bool RShift::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    unsigned int pos;
    CF_CHECK_EQ(gcry_mpi_get_ui(&pos, bn[1].GetPtr()), 0);
    /* noret */ gcry_mpi_rshift(bn.GetResPtr(), bn[0].GetPtr(), pos);
    CF_NORET(bn.CopyResult(res));

end:
    return ret;
}

bool LShift1::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ gcry_mpi_lshift(bn.GetResPtr(), bn[0].GetPtr(), 1);
    CF_NORET(bn.CopyResult(res));

    return true;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_is_neg(bn[0].GetPtr())) );

    return true;
}

bool IsEq::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_cmp(bn[0].GetPtr(), bn[1].GetPtr()) == 0 ? 1 : 0) );

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_cmp_ui(bn[0].GetPtr(), 0) == 0 ? 1 : 0) );

    return true;
}

bool IsOne::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_cmp_ui(bn[0].GetPtr(), 1) == 0 ? 1 : 0) );

    return true;
}

bool MulMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            /* Avoid division by zero */
            CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);
            /* noret */ gcry_mpi_mulm(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
            CF_NORET(bn.CopyResult(res));
            return true;
        case    1:
            {
                CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);

                auto ctx = _gcry_mpi_barrett_init(bn[2].GetPtr(), 1);
                CF_NORET(_gcry_mpi_mul_barrett(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), ctx));
                CF_NORET(bn.CopyResult(res));
                CF_NORET(_gcry_mpi_barrett_free(ctx));
                return true;
            }
            break;
    }

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_addm(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
    CF_NORET(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_subm(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());
    CF_NORET(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    unsigned int pos;
    CF_CHECK_EQ(gcry_mpi_get_ui(&pos, bn[1].GetPtr()), 0);
    res.Set( gcry_mpi_test_bit(bn[0].GetPtr(), pos) ? "1" : "0" );

    ret = true;

end:
    return ret;
}

bool SetBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    unsigned int pos;
    CF_CHECK_EQ(gcry_mpi_get_ui(&pos, bn[1].GetPtr()), 0);
    /* ignore return value */ gcry_mpi_set(res.GetPtr(), bn[0].GetPtr());
    /* noret */ gcry_mpi_set_bit(res.GetPtr(), pos);

    ret = true;

end:
    return ret;
}

bool ClearBit::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    unsigned int pos;
    CF_CHECK_EQ(gcry_mpi_get_ui(&pos, bn[1].GetPtr()), 0);
    /* ignore return value */ gcry_mpi_set(res.GetPtr(), bn[0].GetPtr());
    /* noret */ gcry_mpi_clear_bit(res.GetPtr(), pos);

    ret = true;

end:
    return ret;
}


bool Mod::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;

    GET_WHICH(1);
    switch ( which ) {
        case    0:
            CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);
            /* noret */ gcry_mpi_mod(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            CF_NORET(bn.CopyResult(res));
            return true;
        case    1:
            {
                CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);

                auto ctx = _gcry_mpi_barrett_init(bn[1].GetPtr(), 1);
                CF_NORET(_gcry_mpi_mod_barrett(bn.GetResPtr(), bn[0].GetPtr(), ctx));
                CF_NORET(bn.CopyResult(res));
                CF_NORET(_gcry_mpi_barrett_free(ctx));
                return true;
            }
            break;
    }

end:

    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    /* noret */ gcry_mpi_mul(bn.GetResPtr(), bn[0].GetPtr(), bn[0].GetPtr());
    CF_NORET(bn.CopyResult(res));

    return true;
}

bool NumBits::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_get_nbits(bn[0].GetPtr())) );

    return true;
}

bool Exp::Run(Datasource& ds, Bignum& res, BignumCluster& bn) const {
    (void)ds;

    bool ret = false;
    unsigned int exponent;
    Bignum one;

    CF_CHECK_EQ(gcry_mpi_cmp_ui(bn[0].GetPtr(), 2), 0);
    CF_CHECK_EQ(gcry_mpi_get_ui(&exponent, bn[1].GetPtr()), 0);
    CF_CHECK_EQ(one.Set("1"), true);

    /* noret */ gcry_mpi_mul_2exp(bn.GetResPtr(), one.GetPtr(), exponent);
    CF_NORET(bn.CopyResult(res));

    ret = true;

end:
    return ret;
}

} /* namespace libgcrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
