#include "module.h"
#include <cryptofuzz/util.h>

/* TODO use header */
extern "C" {
    void sha256_1_sse(unsigned char* output, const unsigned char* input, uint64_t count);
    void sha256_1_avx(unsigned char* output, const unsigned char* input, uint64_t count);
    void sha256_4_avx(unsigned char* output, const unsigned char* input, uint64_t count);
    void sha256_8_avx2(unsigned char* output, const unsigned char* input, uint64_t count);
    void sha256_16_avx512(unsigned char* output, const unsigned char* input, uint64_t count);
    void sha256_shani(unsigned char* output, const unsigned char* input, uint64_t count);
}

namespace cryptofuzz {
namespace module {

prysmaticlabs_hashtree::prysmaticlabs_hashtree(void) :
    Module("prysmaticlabs-hashtree") { }

std::optional<component::Digest> prysmaticlabs_hashtree::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;

    if ( op.digestType.Get() != CF_DIGEST("SHA256") ) {
        return std::nullopt;
    }

    if ( op.cleartext.GetSize() != 64 ) {
        return std::nullopt;
    }

    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    uint8_t which = 0;

    try {
        which = ds.Get<uint8_t>() % 6;
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    uint8_t* out = util::malloc(32);

    if ( which == 0 ) {
        CF_NORET(sha256_1_sse(out, op.cleartext.GetPtr(&ds), 1));
    } else if ( which == 1 ) {
        CF_NORET(sha256_1_avx(out, op.cleartext.GetPtr(&ds), 1));
    } else if ( which == 2 ) {
        CF_NORET(sha256_4_avx(out, op.cleartext.GetPtr(&ds), 1));
    } else if ( which == 3 ) {
        CF_NORET(sha256_8_avx2(out, op.cleartext.GetPtr(&ds), 1));
    } else if ( which == 4 ) {
        CF_NORET(sha256_16_avx512(out, op.cleartext.GetPtr(&ds), 1));
    } else if ( which == 5 ) {
        CF_NORET(sha256_shani(out, op.cleartext.GetPtr(&ds), 1));
    } else {
        CF_UNREACHABLE();
    }

    ret = component::Digest(out, 32);

end:
    util::free(out);
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
