#pragma once

#include <botan/bigint.h>

namespace cryptofuzz {
namespace module {
namespace Botan_bignum {

class Bignum {
    private:
        Datasource* ds = nullptr;
        ::Botan::BigInt bn;
        void modify(void);
    public:
        Bignum();
        Bignum(Datasource* ds, const std::string s);
        Bignum(const std::string s);
        Bignum(Datasource* ds, const ::Botan::BigInt& other);
        Bignum(const ::Botan::BigInt& other);
        Bignum(const int i);
        Bignum(const ::Botan::word w);
        ::Botan::BigInt& Ref(void);
        const ::Botan::BigInt& ConstRef(void) const;
};

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
