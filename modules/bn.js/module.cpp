#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "bn.js.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

bn_js::bn_js(void) :
    Module("bn.js"),
    js(new JS()) {

    const std::vector<uint8_t> bc(bn_js_bytecode, bn_js_bytecode + bn_js_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

bn_js::~bn_js(void) {
    delete (JS*)js;
}

std::optional<component::Bignum> bn_js::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const auto json = op.ToJSON().dump();

    const auto res = ((JS*)js)->Run(json);

    if ( res != std::nullopt ) {
        ret = { *res }; 
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
