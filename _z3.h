#if defined(CRYPTOFUZZ_HAVE_Z3)
#pragma once

#include "third_party/json/json.hpp"

namespace cryptofuzz {
namespace Z3 {
    std::optional<nlohmann::json> Generate(const uint64_t calcop);
}
}
#endif /* CRYPTOFUZZ_HAVE_Z3 */
