#include "bn_helper.h"
#include <cryptofuzz/util.h>

namespace cryptofuzz {
namespace module {
namespace relic_bignum {

Bignum::Bignum(Datasource& ds) :
    ds(ds) {
    bn_null(bn);
    bn_new(bn);
}

Bignum::Bignum(const Bignum& other) :
    ds(other.ds) {
    bn_null(bn);
    bn_new(bn);

    /* noret */ bn_copy(bn, other.bn);
}

Bignum::Bignum(const Bignum&& other) :
    ds(other.ds) {
    bn_null(bn);
    bn_new(bn);

    /* noret */ bn_copy(bn, other.bn);
}

void Bignum::baseConversion(void) {
    uint8_t base = 2;
    char* str = nullptr;

    try { base = ds.Get<uint8_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    if ( base > 64 ) {
        base = 64;
    }

    if ( base < 2 ) {
        base = 2;
    }

    {
        const auto size = bn_size_str(bn, base);
        str = (char*)util::malloc(size);
        /* noret */ bn_write_str(str, size, bn, base);
    }

    RLC_TRY {
        /* noret */ bn_read_str(bn, str, strlen(str), base);
    } RLC_CATCH_ANY {
        CF_ASSERT(0, "Cannot read converted string");
    }

    util::free(str);

    return;
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

std::optional<int> Bignum::ToInt(void) {
    static_assert(sizeof(int) == 4);

    std::optional<int> ret = std::nullopt;

    uint8_t b[sizeof(int)];

    CF_CHECK_LTE((size_t)bn_size_bin(bn), sizeof(b));

    /* Throws only if the buffer capacity is unsufficient, so it shouldn't throw */
    /* noret */ bn_write_bin(b, sizeof(b), bn);

    /* Check if sign bit is not set */
    CF_CHECK_EQ(b[0] & 0x80, 0);

    /* Convert to int */
    {
        int r = 0;
        r += b[3];
        r += ((size_t)b[2]) << 8;
        r += ((size_t)b[1]) << 16;
        r += ((size_t)b[0]) << 24;
        ret = r;
    }
end:
    return ret;
}

bn_t& Bignum::Get(void) {
    {
        /* Optionally convert to a random base and back */

        bool convert = false;

        try { convert = ds.Get<bool>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( convert ) {
            baseConversion();
        }
    }

    return bn;
}

Bignum::~Bignum(void) {
    bn_free(bn);
}

} /* namespace relic_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
