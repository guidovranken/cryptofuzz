#include "bn_helper.h"
#include <cryptofuzz/util.h>

namespace cryptofuzz {
namespace module {
namespace relic_bignum {

Bignum::Bignum(void) {
    bn_null(bn);
    bn_new(bn);
}

bool Bignum::Set(const std::string& s) {
	RLC_TRY {
        /* noret */ bn_read_str(bn, s.c_str(), s.size(), 10);
    } RLC_CATCH_ANY {
        return false;
    }

    return true;
}

std::optional<std::string> Bignum::ToString(void) {
    std::string ret;
    const auto size = bn_size_str(bn, 10);
    char* s = (char*)util::malloc(size);
    /* noret */ bn_write_str(s, size, bn, 10);
    ret = std::string(s);
    util::free(s);
    return ret;
}

std::optional<component::Bignum> Bignum::ToComponentBignum(void) {
    std::optional<component::Bignum> ret = std::nullopt;

    auto str = ToString();
    CF_CHECK_NE(str, std::nullopt);
    ret = { str };
end:
    return ret;
}

bn_t& Bignum::Get(void) {
    return bn;
}

Bignum::~Bignum(void) {
    bn_free(a);
}

} /* namespace relic_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
