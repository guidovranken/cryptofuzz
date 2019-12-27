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

    /* noret */ mpz_div(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());
    return true;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_powm(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr());

    return true;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    /* noret */ mpz_gcd(res.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr());

    return true;
}

bool Jacobi::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

    const int jacobi = mpz_jacobi(bn[0].GetPtr(), bn[1].GetPtr());
    res.Set( std::to_string(jacobi ? jacobi : -1) );

    /* XXX */
    //return true;
    return false;
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

} /* namespace libgmp_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
