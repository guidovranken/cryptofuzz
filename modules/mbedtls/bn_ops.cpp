#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include "bn_ops.h"

namespace cryptofuzz {
namespace module {
namespace mbedTLS_bignum {

bool Add::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mbedtls_mpi_add_mpi(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            return true;
        case    1:
            {
                const auto bn1 = bn[1].GetInt32();
                CF_CHECK_NE(bn1, std::nullopt);

                CF_CHECK_EQ(mbedtls_mpi_add_int(res.GetPtr(), bn[0].GetPtr(), *bn1), 0);
            }
            return true;
    }

end:
    return false;
}

bool Sub::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mbedtls_mpi_sub_mpi(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            return true;
        case    1:
            {
                const auto bn1 = bn[1].GetInt32();
                CF_CHECK_NE(bn1, std::nullopt);

                CF_CHECK_EQ(mbedtls_mpi_sub_int(res.GetPtr(), bn[0].GetPtr(), *bn1), 0);
            }
            return true;
    }

end:
    return false;
}

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mbedtls_mpi_mul_mpi(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            return true;
        case    1:
            {
                const auto bn1 = bn[1].GetUint32();
                CF_CHECK_NE(bn1, std::nullopt);

                CF_CHECK_EQ(mbedtls_mpi_mul_int(res.GetPtr(), bn[0].GetPtr(), *bn1), 0);
            }
            return true;
    }

end:
    return false;
}

bool Div::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            CF_CHECK_EQ(mbedtls_mpi_div_mpi(res.GetPtr(), nullptr, bn[0].GetPtr(), bn[1].GetPtr()), 0);
            return true;
        case    1:
            {
                const auto bn1 = bn[1].GetInt32();
                CF_CHECK_NE(bn1, std::nullopt);

                CF_CHECK_EQ(mbedtls_mpi_div_int(res.GetPtr(), nullptr, bn[0].GetPtr(), *bn1), 0);
            }
            return true;
    }

end:
    return false;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_exp_mod(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr(), nullptr), 0);

    ret = true;

end:
    return ret;
}

bool Sqr::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_mul_mpi(res.GetPtr(), bn[0].GetPtr(), bn[0].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_NE(mbedtls_mpi_cmp_int(bn[0].GetPtr(), 0), 0);
    CF_CHECK_NE(mbedtls_mpi_cmp_int(bn[1].GetPtr(), 0), 0);
    CF_CHECK_EQ(mbedtls_mpi_gcd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_inv_mod(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    switch ( ds.Get<uint8_t>() ) {
        case    0:
            res.Set( std::to_string(mbedtls_mpi_cmp_mpi(bn[0].GetPtr(), bn[1].GetPtr())) );
            return true;
        case    1:
            {
                const auto bn1 = bn[1].GetInt32();
                CF_CHECK_NE(bn1, std::nullopt);

                res.Set( std::to_string(mbedtls_mpi_cmp_int(bn[0].GetPtr(), *bn1)) );
            }
            return true;
    }

end:
    return false;
}

bool Abs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_lset(res.GetPtr(), 0), 0);
    CF_CHECK_EQ(mbedtls_mpi_add_abs(res.GetPtr(), res.GetPtr(), bn[0].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool Neg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_lset(res.GetPtr(), 0), 0);
    CF_CHECK_EQ(mbedtls_mpi_sub_mpi(res.GetPtr(), res.GetPtr(), bn[0].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool RShift::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    const auto places = bn[1].GetUint32();
    CF_CHECK_NE(places, std::nullopt);

    CF_CHECK_EQ(mbedtls_mpi_copy(res.GetPtr(), bn[0].GetPtr()), 0);
    CF_CHECK_EQ(mbedtls_mpi_shift_r(res.GetPtr(), *places), 0);

    ret = true;

end:
    return ret;
}

bool LShift1::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_copy(res.GetPtr(), bn[0].GetPtr()), 0);
    CF_CHECK_EQ(mbedtls_mpi_shift_l(res.GetPtr(), 1), 0);

    ret = true;

end:
    return ret;
}

bool IsNeg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mbedtls_mpi_cmp_int(bn[0].GetPtr(), 0) == -1 ? 1 : 0) );

    return true;
}

bool IsEq::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mbedtls_mpi_cmp_mpi(bn[0].GetPtr(), bn[1].GetPtr()) == 0 ? 1 : 0) );

    return true;
}

bool IsZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mbedtls_mpi_cmp_int(bn[0].GetPtr(), 0) == 0 ? 1 : 0) );

    return true;
}

bool IsOne::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mbedtls_mpi_cmp_int(bn[0].GetPtr(), 1) == 0 ? 1 : 0) );

    return true;
}

bool MulMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_mul_mpi(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
    CF_CHECK_EQ(mbedtls_mpi_mod_mpi(res.GetPtr(), res.GetPtr(), bn[2].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool AddMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_add_mpi(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
    CF_CHECK_EQ(mbedtls_mpi_mod_mpi(res.GetPtr(), res.GetPtr(), bn[2].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool SubMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_sub_mpi(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
    CF_CHECK_EQ(mbedtls_mpi_mod_mpi(res.GetPtr(), res.GetPtr(), bn[2].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool SqrMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_mul_mpi(res.GetPtr(), bn[0].GetPtr(), bn[0].GetPtr()), 0);
    CF_CHECK_EQ(mbedtls_mpi_mod_mpi(res.GetPtr(), res.GetPtr(), bn[1].GetPtr()), 0);

    ret = true;

end:
    return ret;
}

bool Bit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    int bit;
    const auto bn1 = bn[1].GetUint32();
    CF_CHECK_NE(bn1, std::nullopt);

    CF_CHECK_GTE(bit = mbedtls_mpi_get_bit(bn[0].GetPtr(), *bn1), 0);
    res.Set( std::to_string(bit) );

    ret = true;

end:
    return ret;
}

bool CmpAbs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    res.Set( std::to_string(mbedtls_mpi_cmp_abs(bn[0].GetPtr(), bn[1].GetPtr())) );

    return true;
}

namespace detail {
    bool SetBit(Bignum& res, std::vector<Bignum>& bn, const bool value) {
        bool ret = false;

        const auto bn1 = bn[1].GetUint32();
        CF_CHECK_NE(bn1, std::nullopt);

        CF_CHECK_EQ(mbedtls_mpi_copy(res.GetPtr(), bn[0].GetPtr()), 0);
        CF_CHECK_EQ(mbedtls_mpi_set_bit(res.GetPtr(), *bn1, value ? 1 : 0), 0);

        ret = true;

end:
        return ret;
    }
}

bool SetBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    return detail::SetBit(res, bn, true);
}

bool ClearBit::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    return detail::SetBit(res, bn, false);
}

bool Mod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;
    bool ret = false;

    CF_CHECK_EQ(mbedtls_mpi_mod_mpi(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);

    ret = true;
end:
    return ret;
}

} /* namespace mbedTLS_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
