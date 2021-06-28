#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "quickjs.bytecode.h"
#include "js.h"

namespace cryptofuzz {
namespace module {

quickjs::quickjs(void) :
    Module("QuickJS"),
    js(new JS()) {

    const std::vector<uint8_t> bc(quickjs_bytecode, quickjs_bytecode + quickjs_bytecode_len);

    ((JS*)js)->SetBytecode(bc);
}

quickjs::~quickjs(void) {
    delete (JS*)js;
}

std::optional<component::Bignum> quickjs::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    auto json = op.ToJSON();

    size_t radix = 0;

    try {
        radix = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    if ( radix < 2 || radix > 36 ) {
        radix = 2;
    }

    json["radix"] = std::to_string(radix);

    const auto res = ((JS*)js)->Run(json.dump());

    if ( res != std::nullopt ) {
        ret = { *res };
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
