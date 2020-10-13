#pragma once

#include <cryptofuzz/components.h>
#include <optional>

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>
}

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_detail {
    
extern WC_RNG rng;

std::optional<int> toCurveID(const component::CurveType& curveType);
std::optional<wc_HashType> toHashType(const component::DigestType& digestType);
void SetGlobalDs(Datasource* ds);
void UnsetGlobalDs(void);

} /* namespace wolfCrypt_detail */
} /* namespace module */
} /* namespace cryptofuzz */
