#include <cryptofuzz/util.h>

#include "bn_helper.h"

namespace cryptofuzz {
namespace module {
namespace Botan_bignum {

void Bignum::modify(void) {
#if defined(CRYPTOFUZZ_BOTAN_IS_ORACLE)
    (void)ds;
#else
    if ( ds == nullptr ) {
        return;
    }

    try {
        /* Binary encode/decode */
        if ( bn >= 0 && ds->Get<bool>() ) {
            uint8_t* encoded = util::malloc(bn.bytes());
            CF_NORET(bn.binary_encode(encoded, bn.bytes()));
            CF_NORET(bn.binary_decode(encoded, bn.bytes()));
            util::free(encoded);
        }

        /* Invoke copy constructor */
        if ( ds->Get<bool>() ) {
            bn = ::Botan::BigInt(bn);
        }
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
#endif
}

Bignum::Bignum() { }

Bignum::Bignum(Datasource* ds, const ::Botan::BigInt& other) :
    ds(ds), bn(other) {
}

Bignum::Bignum(const ::Botan::BigInt& other) :
    bn(other) {
}

Bignum::Bignum(const int i) :
    bn(i)
{ }

Bignum::Bignum(const ::Botan::word w) :
    bn(w)
{ }

Bignum::Bignum(Datasource* ds, const std::string s) :
    ds(ds), bn(s) {
}

Bignum::Bignum(const std::string s) :
    bn(s) {
}

::Botan::BigInt& Bignum::Ref(void) {
    modify();

    return bn;
}

const ::Botan::BigInt& Bignum::ConstRef(void) const {
    return bn;
}

} /* namespace Botan_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
