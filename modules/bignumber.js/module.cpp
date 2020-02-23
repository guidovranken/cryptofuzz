#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "bignumber.js.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

bignumber_js::bignumber_js(void) :
    Module("bignumber.js"),
    js(new JS()) {

    const std::vector<uint8_t> bc(bignumber_js_bytecode, bignumber_js_bytecode + bignumber_js_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

bignumber_js::~bignumber_js(void) {
    delete (JS*)js;
}

std::optional<component::Bignum> bignumber_js::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    auto json = op.ToJSON();

    if ( json["bn0"] == std::string("") ) {
        json["bn0"] = "0";
    }
    if ( json["bn1"] == std::string("") ) {
        json["bn1"] = "0";
    }
    if ( json["bn2"] == std::string("") ) {
        json["bn2"] = "0";
    }
    if ( json["bn3"] == std::string("") ) {
        json["bn3"] = "0";
    }

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = { *res }; 
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
