#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
#include "ctaes.h"
}

namespace cryptofuzz {
namespace module {

Bitcoin::Bitcoin(void) :
    Module("Bitcoin") { }

std::optional<component::Ciphertext> Bitcoin::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
}

std::optional<component::Cleartext> Bitcoin::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
}

} /* namespace module */
} /* namespace cryptofuzz */
