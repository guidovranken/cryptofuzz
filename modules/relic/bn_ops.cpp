#include "bn_ops.h"
#include <cryptofuzz/util.h>

namespace cryptofuzz {
namespace module {
namespace relic_bignum {

bool Add::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_add(res.Get(), bn[0].Get(), bn[1].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool Sub::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_sub(res.Get(), bn[0].Get(), bn[1].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool Mul::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    try {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                RLC_TRY {
                    /* noret */ bn_mul(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    1:
                RLC_TRY {
                    /* noret */ bn_mul_basic(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    2:
                RLC_TRY {
                    /* noret */ bn_mul_comba(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    3:
                RLC_TRY {
                    /* noret */ bn_mul_karat(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
        }
    } catch ( ... ) { }

    return false;
}

bool Sqr::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    try {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                RLC_TRY {
                    /* noret */ bn_sqr(res.Get(), bn[0].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    1:
                RLC_TRY {
                    /* noret */ bn_sqr_basic(res.Get(), bn[0].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    2:
                RLC_TRY {
                    /* noret */ bn_sqr_comba(res.Get(), bn[0].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    3:
                RLC_TRY {
                    /* noret */ bn_sqr_karat(res.Get(), bn[0].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
        }
    } catch ( ... ) { }

    return false;
}

bool Div::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_div(res.Get(), bn[0].Get(), bn[1].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool GCD::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    try {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                RLC_TRY {
                    /* noret */ bn_gcd(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    1:
                RLC_TRY {
                    /* noret */ bn_gcd_basic(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    2:
                RLC_TRY {
                    /* noret */ bn_gcd_lehme(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    3:
                RLC_TRY {
                    /* noret */ bn_gcd_stein(res.Get(), bn[0].Get(), bn[1].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
        }
    } catch ( ... ) { }

    return false;
}

bool LCM::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_lcm(res.Get(), bn[0].Get(), bn[1].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool InvMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_mod_inv(res.Get(), bn[0].Get(), bn[1].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool LShift1::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    try {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                RLC_TRY {
                    bn_lsh(res.Get(), bn[0].Get(), 1);
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    1:
                RLC_TRY {
                    bn_dbl(res.Get(), bn[0].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
        }
    } catch ( ... ) { }

    return false;
}

bool Jacobi::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_smb_jac(res.Get(), bn[0].Get(), bn[1].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool Cmp::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    bool ret = false;
    (void)ds;

	RLC_TRY {
        const auto r = bn_cmp(bn[0].Get(), bn[1].Get());

        if ( r == RLC_EQ ) {
            CF_CHECK_TRUE(res.Set("0"));
        } else if ( r == RLC_LT ) {
            CF_CHECK_TRUE(res.Set("-1"));
        } else if ( r == RLC_GT ) {
            CF_CHECK_TRUE(res.Set("1"));
        } else {
            CF_UNREACHABLE();
        }

        ret = true;
    } RLC_CATCH_ANY {
        /* Fall through */
    }

end:
    return ret;
}

bool Mod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_mod(res.Get(), bn[0].Get(), bn[1].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool IsEven::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    bool ret = false;
    (void)ds;

	RLC_TRY {
        const auto r = bn_is_even(bn[0].Get());
        if ( r == 1 ) {
            CF_CHECK_TRUE(res.Set("1"));
        } else if ( r == 0 ) {
            CF_CHECK_TRUE(res.Set("0"));
        } else {
            CF_UNREACHABLE();
        }

        ret = true;
    } RLC_CATCH_ANY {
        /* Fall through */
    }

end:
    return ret;
}

bool IsOdd::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    bool ret = false;
    (void)ds;

	RLC_TRY {
        const auto r = bn_is_even(bn[0].Get());
        if ( r == 1 ) {
            CF_CHECK_TRUE(res.Set("0"));
        } else if ( r == 0 ) {
            CF_CHECK_TRUE(res.Set("1"));
        } else {
            CF_UNREACHABLE();
        }

        ret = true;
    } RLC_CATCH_ANY {
        /* Fall through */
    }

end:
    return ret;
}

bool IsZero::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    bool ret = false;
    (void)ds;

	RLC_TRY {
        const auto r = bn_is_zero(bn[0].Get());
        if ( r == 1 ) {
            CF_CHECK_TRUE(res.Set("1"));
        } else if ( r == 0 ) {
            CF_CHECK_TRUE(res.Set("0"));
        } else {
            CF_UNREACHABLE();
        }

        ret = true;
    } RLC_CATCH_ANY {
        /* Fall through */
    }

end:
    return ret;
}

bool Neg::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_neg(res.Get(), bn[0].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool Sqrt::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_srt(res.Get(), bn[0].Get());

        /* Says SQRT(16) is 5 */
        return false;
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool Abs::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    (void)ds;

	RLC_TRY {
        /* noret */ bn_abs(res.Get(), bn[0].Get());
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

bool ExpMod::Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const {
    try {
        switch ( ds.Get<uint8_t>() ) {
            case    0:
                RLC_TRY {
                    /* noret */ bn_mxp(res.Get(), bn[0].Get(), bn[1].Get(), bn[2].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    1:
                RLC_TRY {
                    /* noret */ bn_mxp_basic(res.Get(), bn[0].Get(), bn[1].Get(), bn[2].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    2:
                RLC_TRY {
                    /* noret */ bn_mxp_slide(res.Get(), bn[0].Get(), bn[1].Get(), bn[2].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
            case    3:
                RLC_TRY {
                    /* noret */ bn_mxp_monty(res.Get(), bn[0].Get(), bn[1].Get(), bn[2].Get());
                } RLC_CATCH_ANY {
                    return false;
                }
                return true;
        }
    } catch ( ... ) { }

    return false;
}

} /* namespace relic_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
