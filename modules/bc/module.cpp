#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
#include <number.h>
void rt_warn (const char *mesg ,...) {
    (void)mesg;
}
void rt_error (const char *mesg ,...) {
    (void)mesg;
}
void out_of_memory (void) {
    abort();
}
}

namespace cryptofuzz {
namespace module {

bc::bc(void) :
    Module("bc") {
    bc_init_numbers();
}

std::optional<component::Bignum> bc::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bc_num bn[3], res;

    CF_NORET(bc_init_num(&(bn[0])));
    CF_NORET(bc_init_num(&(bn[1])));
    CF_NORET(bc_init_num(&(bn[2])));
    CF_NORET(bc_init_num(&res));

    {
        auto s = op.bn0.ToString();
        CF_NORET(bc_str2num(&(bn[0]), s.data(), 0));
    }
    {
        auto s = op.bn1.ToString();
        CF_NORET(bc_str2num(&(bn[1]), s.data(), 0));
    }
    {
        auto s = op.bn2.ToString();
        CF_NORET(bc_str2num(&(bn[2]), s.data(), 0));
    }

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            CF_NORET(bc_add(bn[0], bn[1], &res, 0));
            break;
        case    CF_CALCOP("Sub(A,B)"):
            CF_NORET(bc_sub(bn[0], bn[1], &res, 0));
            break;
        case    CF_CALCOP("Mul(A,B)"):
            CF_NORET(bc_multiply(bn[0], bn[1], &res, 0));
            break;
        case    CF_CALCOP("Div(A,B)"):
            CF_CHECK_EQ(bc_divide(bn[0], bn[1], &res, 0), 0);
            break;
        case    CF_CALCOP("Mod(A,B)"):
            CF_CHECK_EQ(bc_modulo(bn[0], bn[1], &res, 0), 0);
            break;
        case    CF_CALCOP("Exp(A,B)"):
            CF_NORET(bc_raise(bn[0], bn[1], &res, 0));
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            CF_CHECK_NE(op.bn0.ToTrimmedString(), "0");
            CF_CHECK_NE(op.bn1.ToTrimmedString(), "0");
            CF_CHECK_LTE(op.bn0.GetSize(), 20);
            CF_CHECK_LTE(op.bn1.GetSize(), 20);
            CF_CHECK_EQ(bc_raisemod(bn[0], bn[1], bn[2], &res, 0), 0);
            break;
        case    CF_CALCOP("Sqrt(A)"):
            CF_CHECK_EQ(bc_sqrt(&(bn[0]), 0), 1);
            bc_free_num(&res);
            res = bc_copy_num(bn[0]);
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            ret = std::to_string(bc_compare(bn[0], bn[1]));
            goto end;
            break;
        case    CF_CALCOP("IsZero(A)"):
            ret = std::to_string(bc_is_zero(bn[0]));
            goto end;
            break;
        case    CF_CALCOP("IsNeg(A)"):
            ret = std::to_string(bc_is_neg(bn[0]));
            goto end;
            break;
        default:
            goto end;
    }

    {
        const auto s = bc_num2str(res);
        ret = std::string(s);
        free(s);
    }

end:

    bc_free_num(&(bn[0]));
    bc_free_num(&(bn[1]));
    bc_free_num(&(bn[2]));
    bc_free_num(&res);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
