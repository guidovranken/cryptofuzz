#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
    #include "cryptofuzz.h"
}

namespace cryptofuzz {
namespace module {

Golang::Golang(void) :
    Module("Golang") {
}

std::string Golang::getResult(void) const {
    auto res = Golang_Cryptofuzz_GetResult();
    std::string ret(res);
    free(res);
    return ret;
}

nlohmann::json Golang::getJsonResult(void) const {
    return nlohmann::json::parse(getResult());
}

template <class T> std::optional<T> Golang::getResultAs(void) const {
    std::optional<T> ret = std::nullopt;

    try {
        ret = T(getJsonResult());
    } catch ( ... ) { }

    return ret;
}

static GoSlice toGoSlice(std::string in) {
    return {in.data(), static_cast<GoInt>(in.size()), static_cast<GoInt>(in.size())};
}

std::optional<component::Digest> Golang::OpDigest(operation::Digest& op) {
    auto jsonStr = op.ToJSON().dump();
    Golang_Cryptofuzz_OpDigest(toGoSlice(jsonStr));

    return getResultAs<component::Digest>();
}

std::optional<component::Key> Golang::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    auto jsonStr = op.ToJSON().dump();
    Golang_Cryptofuzz_OpKDF_SCRYPT(toGoSlice(jsonStr));

    return getResultAs<component::Key>();
}

std::optional<component::Key> Golang::OpKDF_HKDF(operation::KDF_HKDF& op) {
    auto jsonStr = op.ToJSON().dump();
    Golang_Cryptofuzz_OpKDF_HKDF(toGoSlice(jsonStr));

    return getResultAs<component::Key>();
}

std::optional<component::Key> Golang::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    auto jsonStr = op.ToJSON().dump();
    Golang_Cryptofuzz_OpKDF_PBKDF2(toGoSlice(jsonStr));

    return getResultAs<component::Key>();
}

} /* namespace module */
} /* namespace cryptofuzz */
