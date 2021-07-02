#include "bn_ops.h"
#include <iostream>

namespace cryptofuzz {
namespace module {

namespace wolfCrypt_detail {
#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
    extern bool disableAllocationFailures;
    extern bool haveAllocFailure;
#endif
} /* namespace wolfCrypt_detail */

namespace wolfCrypt_bignum {

Bignum::read_radix_error_t Bignum::read_radix(mp_int* dest, const std::string& str, const size_t base) {
    return read_radix(dest, str.c_str(), base);
}

Bignum::read_radix_error_t Bignum::read_radix(mp_int* dest, const char* str, const size_t base) {
    Bignum::read_radix_error_t ret;

    /* Create a temporary variable for storing the result of mp_read_radix,
     * because if mp_read_radix fails (e.g. due to allocation failure),
     * it will set the value of the destination variable to 0.
     *
     * See OSS-Fuzz 31709 / ZD 11834 for discussion. */
    auto newMp = (mp_int*)util::malloc(sizeof(mp_int));
    if ( mp_init(newMp) != MP_OKAY ) {
        util::free(newMp);
        return READ_RADIX_FAIL_MEMORY;
    }

    wolfCrypt_detail::haveAllocFailure = false;
    if ( mp_read_radix(newMp, str, base) != MP_OKAY ) {
        ret = wolfCrypt_detail::haveAllocFailure ? READ_RADIX_FAIL_MEMORY : READ_RADIX_FAIL_OTHER;
        goto end;
    }

    wolfCrypt_detail::haveAllocFailure = false;
    if ( mp_copy(newMp, dest) != MP_OKAY ) {
        ret = wolfCrypt_detail::haveAllocFailure ? READ_RADIX_FAIL_MEMORY : READ_RADIX_FAIL_OTHER;
        goto end;
    }

    ret = READ_RADIX_OK;

end:
    CF_NORET(mp_clear(newMp));
    util::free(newMp);

    return ret;
}

void Bignum::baseConversion(void) const {
#if !defined(WOLFSSL_SP_MATH)
    uint8_t base = 2;
    char* str = nullptr;

    try { base = ds.Get<uint8_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

#if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
    std::cout << "Convert to base " << std::to_string(base) << " and back" << std::endl;
#endif
    {
        int size;
        CF_CHECK_EQ(mp_radix_size(mp, base, &size), MP_OKAY);
        CF_ASSERT(size > 0, "Output of mp_radix_size is 0 or less");

        str = (char*)util::malloc(size);

#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL) || !defined(USE_FAST_MATH)
        CF_CHECK_EQ(mp_toradix(mp, str, base), MP_OKAY);
#else
        wolfCrypt_detail::haveAllocFailure = false;
        CF_ASSERT(
                    mp_toradix(mp, str, base) == MP_OKAY ||
                    wolfCrypt_detail::haveAllocFailure ||
                    base < 2 ||
                    base > 64,
                    "wolfCrypt cannot convert mp to string");

        /* If allocation failure occurred, then do not use 'str' */
        CF_CHECK_FALSE(wolfCrypt_detail::haveAllocFailure);
#endif

        {
            const auto ret = read_radix(mp, str, base);
            CF_ASSERT(ret == READ_RADIX_OK || ret == READ_RADIX_FAIL_MEMORY, "wolfCrypt cannot parse the output of mp_toradix");
        }
    }

end:
    util::free(str);
#endif
}

void Bignum::binaryConversion(void) const {
    uint8_t* data = nullptr;

    CF_CHECK_EQ(mp_isneg(mp), 0);

    {
        const auto size = mp_unsigned_bin_size(mp);
        CF_ASSERT(size >= 0, "mp_unsigned_bin_size returned negative value");

        data = util::malloc(size);
        CF_CHECK_EQ(mp_to_unsigned_bin_len(mp, data, size), MP_OKAY);

        CF_ASSERT(mp_read_unsigned_bin(mp, data, size) == MP_OKAY, "Cannot parse output of mp_to_unsigned_bin_len");
    }

end:
    util::free(data);
}

Bignum::Bignum(Datasource& ds) :
    ds(ds) {
    mp = (mp_int*)util::malloc(sizeof(mp_int));
    if ( mp_init(mp) != MP_OKAY ) {
        util::free(mp);
        throw std::exception();
    }
}

Bignum::Bignum(mp_int* mp, Datasource& ds) :
    mp(mp),
    ds(ds),
    noFree(true)
{ }

Bignum::Bignum(const Bignum& other) :
    ds(other.ds) {
    mp = (mp_int*)util::malloc(sizeof(mp_int));
    if ( mp_init(mp) != MP_OKAY ) {
        util::free(mp);
        throw std::exception();
    }
    if ( mp_copy(other.mp, mp) != MP_OKAY ) {
        util::free(mp);
        throw std::exception();
    }
}

Bignum::Bignum(const Bignum&& other) :
    ds(other.ds) {
    mp = (mp_int*)util::malloc(sizeof(mp_int));
    if ( mp_init(mp) != MP_OKAY ) {
        util::free(mp);
        throw std::exception();
    }
    if ( mp_copy(other.mp, mp) != MP_OKAY ) {
        util::free(mp);
        throw std::exception();
    }
}

Bignum::~Bignum() {
    if ( noFree == false ) {
        CF_NORET(mp_clear(mp));
        util::free(mp);
    }
}

void Bignum::SetNoFree(void) {
    noFree = true;
}

bool Bignum::Set(const std::string s) {
    bool ret = false;

    bool hex = false;
    try {
        hex = ds.Get<bool>();
    } catch ( ... ) { }

#if defined(WOLFSSL_SP_MATH)
    hex = true;
#endif

    if ( hex == true ) {
        CF_CHECK_EQ(read_radix(mp, util::DecToHex(s), 16), READ_RADIX_OK);
    } else {
        CF_CHECK_EQ(read_radix(mp, s, 10), READ_RADIX_OK);
    }

    ret = true;
end:
    return ret;
}

bool Bignum::Set(const component::Bignum i) {
    bool ret = false;

    CF_CHECK_EQ(Set(i.ToString()), true);

    ret = true;
end:
    return ret;
}

mp_int* Bignum::GetPtr(void) const {
    {
#if defined(WOLFSSL_SP_MATH) || defined(WOLFSSL_SP_MATH_ALL)
        CF_ASSERT(mp->used <= mp->size, "used is larger than size");
#elif !defined(USE_FAST_MATH)
        CF_ASSERT(mp->used <= mp->alloc, "used is larger than size");
#endif
    }

    {
        /* Optionally clamp the bignum. This should not affect its value. */

        bool clamp = false;

        try { clamp = ds.Get<bool>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( clamp ) {
            /* Implemented as a macro so CF_NORET cannot be used here */
            /* noret */ mp_clamp(mp);
        }
    }

    {
        /* Optionally convert to a random base and back */

        bool convert = false;

        try { convert = ds.Get<bool>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( convert ) {
            baseConversion();
        }
    }

    {
        /* Optionally convert to bytes and back */

        bool convert = false;

        try { convert = ds.Get<bool>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( convert ) {
            binaryConversion();
        }
    }

    return mp;
}

mp_int* Bignum::GetPtrDirect(void) const {
    return mp;
}

std::optional<uint64_t> Bignum::AsUint64(void) const {
    std::optional<uint64_t> ret = std::nullopt;
    uint64_t v = 0;

#if !defined(WOLFSSL_SP_MATH)
    CF_CHECK_EQ(mp_isneg(mp), 0);
#endif
    CF_CHECK_LTE(mp_count_bits(mp), (int)(sizeof(v) * 8));
    CF_CHECK_EQ(mp_to_unsigned_bin_len(mp, (uint8_t*)&v, sizeof(v)), MP_OKAY);
    v =
        ((v & 0xFF00000000000000) >> 56) |
        ((v & 0x00FF000000000000) >> 40) |
        ((v & 0x0000FF0000000000) >> 24) |
        ((v & 0x000000FF00000000) >>  8) |
        ((v & 0x00000000FF000000) <<  8) |
        ((v & 0x0000000000FF0000) << 24) |
        ((v & 0x000000000000FF00) << 40) |
        ((v & 0x00000000000000FF) << 56);

    ret = v;
end:
    return ret;
}

std::optional<std::string> Bignum::ToDecString(void) {
    std::optional<std::string> ret = std::nullopt;
    char* str = nullptr;

#if defined(WOLFSSL_SP_MATH)
    str = (char*)util::malloc(8192);

    CF_CHECK_EQ(mp_tohex(mp, str), MP_OKAY);
    ret = { util::HexToDec(str) };
#else
    bool hex = false;
    int size;

    try {
        hex = ds.Get<bool>();
    } catch ( ... ) { }


    if ( hex == true ) {
        CF_CHECK_EQ(mp_radix_size(mp, 16, &size), MP_OKAY);
        CF_ASSERT(size > 0, "Output of mp_radix_size is 0 or less");

        str = (char*)util::malloc(size+1);

        CF_CHECK_EQ(mp_tohex(mp, str), MP_OKAY);
        ret = { util::HexToDec(str) };
    } else {
        CF_CHECK_EQ(mp_radix_size(mp, 10, &size), MP_OKAY);
        CF_ASSERT(size > 0, "Output of mp_radix_size is 0 or less");

        str = (char*)util::malloc(size);

        CF_CHECK_EQ(mp_toradix(mp, str, 10), MP_OKAY);
        ret = std::string(str);
    }
#endif

end:
    free(str);

    return ret;
}

std::optional<component::Bignum> Bignum::ToComponentBignum(void) {
    std::optional<component::Bignum> ret = std::nullopt;

    auto str = ToDecString();
    CF_CHECK_NE(str, std::nullopt);
    ret = { str };
end:
    return ret;
}

bool Bignum::ToBin(uint8_t* dest, const size_t size) {
    bool ret = false;

    const auto required = mp_unsigned_bin_size(GetPtr());
    CF_ASSERT(required >= 0, "mp_unsigned_bin_size returned negative value");

    CF_CHECK_GTE(size, static_cast<size_t>(required));
    CF_CHECK_EQ(mp_to_unsigned_bin_len(GetPtr(), dest, size), MP_OKAY);

    ret = true;
end:
    return ret;
}


std::optional<std::vector<uint8_t>> Bignum::ToBin(Datasource& ds, const component::Bignum b, std::optional<size_t> size) {
    std::optional<std::vector<uint8_t>> ret = std::nullopt;
    std::vector<uint8_t> v;
    Bignum bn(ds);
    uint16_t padding = 0;

    CF_CHECK_EQ(bn.Set(b), true);
    if ( size != std::nullopt ) {
        v.resize(*size);
    } else {
        try {
            padding = ds.Get<uint16_t>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        v.resize( mp_unsigned_bin_size(bn.GetPtr()) + padding );
    }

    CF_CHECK_EQ(bn.ToBin(v.data(), v.size()), true);

    ret = v;
end:
    return ret;
}

bool Bignum::ToBin(Datasource& ds, const component::Bignum b, uint8_t* dest, const size_t size) {
    bool ret = false;
    Bignum bn(ds);

    CF_CHECK_EQ(bn.Set(b), true);
    CF_CHECK_EQ(bn.ToBin(dest, size), true);

    ret = true;
end:
    return ret;
}

bool Bignum::ToBin(Datasource& ds, const component::BignumPair b, uint8_t* dest, const size_t size) {
    CF_ASSERT((size % 2) == 0, "Input size is not multiple of 2 in Bignum::ToBin");

    bool ret = false;
    const auto halfSize = size / 2;

    CF_CHECK_EQ(ToBin(ds, b.first, dest, halfSize), true);
    CF_CHECK_EQ(ToBin(ds, b.second, dest + halfSize, halfSize), true);

    ret = true;
end:
    return ret;
}

std::optional<component::Bignum> Bignum::BinToBignum(Datasource& ds, const uint8_t* src, const size_t size) {
    std::optional<component::Bignum> ret = std::nullopt;

    wolfCrypt_bignum::Bignum bn(ds);
    CF_CHECK_EQ(mp_read_unsigned_bin(bn.GetPtr(), src, size), MP_OKAY);

    ret = bn.ToComponentBignum();

end:
    return ret;
}

std::optional<component::BignumPair> Bignum::BinToBignumPair(Datasource& ds, const uint8_t* src, const size_t size) {
    CF_ASSERT((size % 2) == 0, "Input size is not multiple of 2 in Bignum::BinToBignumPair");

    std::optional<component::BignumPair> ret = std::nullopt;
    std::optional<component::Bignum> A, B;
    const auto halfSize = size / 2;

    {
        wolfCrypt_bignum::Bignum bn(ds);
        CF_CHECK_EQ(mp_read_unsigned_bin(bn.GetPtr(), src, halfSize), MP_OKAY);
        CF_CHECK_NE(A = bn.ToComponentBignum(), std::nullopt);
    }

    {
        wolfCrypt_bignum::Bignum bn(ds);
        CF_CHECK_EQ(mp_read_unsigned_bin(bn.GetPtr(), src + halfSize, halfSize), MP_OKAY);
        CF_CHECK_NE(B = bn.ToComponentBignum(), std::nullopt);
    }


    ret = {A->ToTrimmedString(), B->ToTrimmedString()};

end:
    return ret;
}

bool Bignum::operator==(const Bignum& rhs) const {
    return mp_cmp(GetPtr(), rhs.GetPtr()) == MP_EQ;
}

BignumCluster::BignumCluster(Datasource& ds, Bignum bn0, Bignum bn1, Bignum bn2, Bignum bn3) :
    ds(ds),
    bn({bn0, bn1, bn2, bn3})
{ }

BignumCluster::~BignumCluster() {
    for (size_t i = 0; i < 4; i++) {
        if ( cache.bn[i] == nullptr ) {
            continue;
        }

        mp_clear(cache.bn[i]);
        util::free(cache.bn[i]);
    }
}

Bignum& BignumCluster::operator[](const size_t index) {
    CF_ASSERT(index < bn.size(), "Invalid index requested in BignumCluster::operator[]");

    try {
        /* Rewire? */
        if ( ds.Get<bool>() == true ) {
            /* Pick a random bignum */
            const auto newIndex = ds.Get<uint8_t>() % 4;

            /* Same value? */
            if ( bn[newIndex] == bn[index] ) {
                /* Then return reference to other bignum */
                return bn[newIndex];
            }

            /* Fall through */
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    return bn[index];
}

bool BignumCluster::Set(const size_t index, const std::string s) {
    CF_ASSERT(index < bn.size(), "Invalid index requested in BignumCluster::Set");

    return bn[index].Set(s);
}

mp_int* BignumCluster::GetDestPtr(const size_t index) {
    /* Because it is requested as a destination pointer,
     * this bignum will be altered, hence invalidate
     * the cache
     */
    InvalidateCache();

    return bn[index].GetPtr();
}

void BignumCluster::Save(void) {
    for (size_t i = 0; i < 4; i++) {
        mp_int* cached_mp = (mp_int*)util::malloc(sizeof(mp_int));

        wolfCrypt_detail::disableAllocationFailures = true;

        CF_ASSERT(mp_init(cached_mp) == MP_OKAY, "mp_init failed unexpectedly");
        CF_ASSERT(mp_copy(bn[i].GetPtrDirect(), cached_mp) == MP_OKAY, "mp_copy failed unexpectedly");

        wolfCrypt_detail::disableAllocationFailures = false;

        cache.bn[i] = cached_mp;
    }
}

void BignumCluster::InvalidateCache(void) {
    cache.invalid = true;
}

bool BignumCluster::EqualsCache(void) const {
    if ( cache.invalid == true ) {
        return true;
    }

    for (size_t i = 0; i < 4; i++) {
        if ( cache.bn[i] == nullptr ) {
            continue;
        }

        wolfCrypt_detail::disableAllocationFailures = true;

        if ( mp_cmp(bn[i].GetPtrDirect(), cache.bn[i]) != MP_EQ ) {
#if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
            char str[8192];

            std::cout << "Bignum with index " << std::to_string(i) << " was changed" << std::endl;

            wolfCrypt_detail::disableAllocationFailures = true;

            CF_ASSERT(mp_tohex(cache.bn[i], str) == MP_OKAY, "mp_tohex failed unexpectedly");
            printf("it was: %s\n", str);

            CF_ASSERT(mp_tohex(bn[i].GetPtrDirect(), str) == MP_OKAY, "mp_tohex failed unexpectedly");
            printf("it is now %s\n", str);

#endif
            wolfCrypt_detail::disableAllocationFailures = false;

            return false;
        }

        wolfCrypt_detail::disableAllocationFailures = false;
    }

    return true;
}

} /* namespace wolfCrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
