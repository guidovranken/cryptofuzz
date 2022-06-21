#pragma once

#include <optional>
#include <boost/multiprecision/cpp_int.hpp>
#include "third_party/json/json.hpp"

namespace cryptofuzz {
namespace mutator {
namespace ExpModGenerator {
    using namespace boost::multiprecision;
    std::optional<nlohmann::json> generate_exp_mod(const std::string& _result);
} /* ExpModGenerator */
} /* mutator */
} /* cryptofuzz */
