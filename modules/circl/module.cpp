#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <boost/lexical_cast.hpp>

extern "C" {
    #include "cryptofuzz.h"
}

namespace cryptofuzz {
namespace module {

circl::circl(void) :
    Module("circl") {
}

std::string circl::getResult(void) const {
    auto res = circl_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

std::optional<nlohmann::json> circl::getJsonResult(void) const {
    const auto res = getResult();
    if ( res.empty() ) {
        return std::nullopt;
    }

    try {
        return nlohmann::json::parse(getResult());
    } catch ( std::exception e ) {
        /* Must always parse correctly non-empty strings */
        abort();
    }
}

template <class T> std::optional<T> circl::getResultAs(void) const {
    std::optional<T> ret = std::nullopt;

    auto j = getJsonResult();
    if ( j != std::nullopt ) {
        ret = T(*j);
    }

    return ret;
}

static GoSlice toGoSlice(std::string& in) {
    return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
}

std::optional<component::ECC_Point> circl::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    auto jsonStr = op.ToJSON().dump();
    circl_Cryptofuzz_OpECC_Point_Add(toGoSlice(jsonStr));

    return getResultAs<component::ECC_Point>();
}

std::optional<component::ECC_Point> circl::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    auto jsonStr = op.ToJSON().dump();
    circl_Cryptofuzz_OpECC_Point_Mul(toGoSlice(jsonStr));

    return getResultAs<component::ECC_Point>();
}

std::optional<component::ECC_Point> circl::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    auto jsonStr = op.ToJSON().dump();
    circl_Cryptofuzz_OpECC_Point_Dbl(toGoSlice(jsonStr));

    return getResultAs<component::ECC_Point>();
}

} /* namespace module */
} /* namespace cryptofuzz */
