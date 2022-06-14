#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "jsbn.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

jsbn::jsbn(void) :
    Module("jsbn"),
    js(new JS()) {

    const std::vector<uint8_t> bc(jsbn_bytecode, jsbn_bytecode + jsbn_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

jsbn::~jsbn(void) {
    delete (JS*)js;
}

std::optional<component::Bignum> jsbn::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.calcOp.Is(CF_CALCOP("ExpMod(A,B,C)")) ) {
        if ( op.bn1.ToTrimmedString() == "0" ) {
            return std::nullopt;
        }
        if ( op.bn2.ToTrimmedString() == "0" ) {
            return std::nullopt;
        }

        if ( op.bn0.ToTrimmedString().size() > 500 ) {
            return std::nullopt;
        }
        if ( op.bn1.ToTrimmedString().size() > 500 ) {
            return std::nullopt;
        }
        if ( op.bn2.ToTrimmedString().size() > 500 ) {
            return std::nullopt;
        }
    } else if ( op.calcOp.Is(CF_CALCOP("InvMod(A,B)")) ) {
        if ( op.bn0.ToTrimmedString() == "0" ) {
            return std::nullopt;
        }
    }

    const auto json = op.ToJSON().dump();

    const auto res = ((JS*)js)->Run(json);

    if ( res != std::nullopt ) {
        ret = { *res };
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
