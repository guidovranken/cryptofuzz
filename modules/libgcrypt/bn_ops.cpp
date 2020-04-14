#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

namespace cryptofuzz {
namespace module {
namespace libgcrypt_bignum {

bool Add::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            /* noret */ gcry_mpi_add(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            return true;
        case    1:
            {
                unsigned int ui;
                CF_CHECK_EQ(gcry_mpi_get_ui(&ui, bn[1].GetPtr()), 0);
                /* noret */ gcry_mpi_add_ui(res.GetPtr(), bn[0].GetPtr(), ui);
                return true;
            }
            break;
    }

end:
    return false;
}

bool Sub::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            /* noret */ gcry_mpi_sub(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            return true;
        case    1:
            {
                unsigned int ui;
                CF_CHECK_EQ(gcry_mpi_get_ui(&ui, bn[1].GetPtr()), 0);
                /* noret */ gcry_mpi_sub_ui(res.GetPtr(), bn[0].GetPtr(), ui);
                return true;
            }
            break;
    }

end:
    return false;
}

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            /* noret */ gcry_mpi_mul(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
            return true;
        case    1:
            {
                unsigned int ui;
                CF_CHECK_EQ(gcry_mpi_get_ui(&ui, bn[1].GetPtr()), 0);
                /* noret */ gcry_mpi_mul_ui(res.GetPtr(), bn[0].GetPtr(), ui);
                return true;
            }
            break;
        case    2:
            {
                goto end;
                /* TODO gcry_mpi_mul_2exp */
            }
            break;
    }

end:
    return false;
}

bool Div::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_div(res.GetPtr(), nullptr, bn[0].GetPtr(), bn[1].GetPtr(), 0);

    ret = true;

end:
    return ret;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_powm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[0].GetPtr(), 0), 0);
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);
    /* return value not important */ gcry_mpi_gcd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[1].GetPtr(), 0), 0);
    CF_CHECK_EQ(gcry_mpi_invm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 1);

    ret = true;

end:
    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
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

bool Abs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* ignore return value */ gcry_mpi_set(res.GetPtr(), bn[0].GetPtr());
    /* noret */ gcry_mpi_abs(res.GetPtr());

    return true;
}

bool Neg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ gcry_mpi_neg(res.GetPtr(), bn[0].GetPtr());

    return true;
}

bool RShift::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    unsigned int pos;
    CF_CHECK_EQ(gcry_mpi_get_ui(&pos, bn[1].GetPtr()), 0);
    /* noret */ gcry_mpi_rshift(res.GetPtr(), bn[0].GetPtr(), pos);

end:
    return ret;
}

bool LShift1::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ gcry_mpi_lshift(res.GetPtr(), bn[0].GetPtr(), 1);

    return true;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_is_neg(bn[0].GetPtr())) );

    return true;
}

bool IsEq::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_cmp(bn[0].GetPtr(), bn[1].GetPtr()) == 0 ? 1 : 0) );

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_cmp_ui(bn[0].GetPtr(), 0) == 0 ? 1 : 0) );

    return true;
}

bool IsOne::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(gcry_mpi_cmp_ui(bn[0].GetPtr(), 1) == 0 ? 1 : 0) );

    return true;
}

bool MulMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_mulm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_addm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    /* Avoid division by zero */
    CF_CHECK_NE(gcry_mpi_cmp_ui(bn[2].GetPtr(), 0), 0);
    /* noret */ gcry_mpi_subm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    bool ret = false;

    unsigned int pos;
    CF_CHECK_EQ(gcry_mpi_get_ui(&pos, bn[1].GetPtr()), 0);
    res.Set( gcry_mpi_test_bit(bn[0].GetPtr(), pos) ? "1" : "0" );

    ret = true;

end:
    return ret;
}

bool SetBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
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

bool ClearBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
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

} /* namespace libgcrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
