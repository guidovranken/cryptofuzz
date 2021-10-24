#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    #include <nimcrypto_harness.h>
}

namespace cryptofuzz {
namespace module {

nimcrypto::nimcrypto(void) :
    Module("nimcrypto") { }

std::optional<component::Digest> nimcrypto::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;

    if ( op.digestType.Is(CF_DIGEST("KECCAK_224")) ) {
        uint8_t hash[28];
        const auto size = cryptofuzz_nimcrypto_keccak_224((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("KECCAK_256")) ) {
        uint8_t hash[32];
        const auto size = cryptofuzz_nimcrypto_keccak_256((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("KECCAK_384")) ) {
        uint8_t hash[48];
        const auto size = cryptofuzz_nimcrypto_keccak_384((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("KECCAK_512")) ) {
        uint8_t hash[64];
        const auto size = cryptofuzz_nimcrypto_keccak_512((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S224")) ) {
        uint8_t hash[28];
        const auto size = cryptofuzz_nimcrypto_blake2s_224((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S256")) ) {
        uint8_t hash[32];
        const auto size = cryptofuzz_nimcrypto_blake2s_256((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("BLAKE2B384")) ) {
        uint8_t hash[48];
        const auto size = cryptofuzz_nimcrypto_blake2b_384((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("BLAKE2B512")) ) {
        uint8_t hash[64];
        const auto size = cryptofuzz_nimcrypto_blake2b_512((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("RIPEMD128")) ) {
        uint8_t hash[16];
        const auto size = cryptofuzz_nimcrypto_ripemd_128((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("RIPEMD160")) ) {
        uint8_t hash[20];
        const auto size = cryptofuzz_nimcrypto_ripemd_160((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("RIPEMD256")) ) {
        uint8_t hash[32];
        const auto size = cryptofuzz_nimcrypto_ripemd_256((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    } else if ( op.digestType.Is(CF_DIGEST("RIPEMD320")) ) {
        uint8_t hash[40];
        const auto size = cryptofuzz_nimcrypto_ripemd_320((uint8_t*)op.cleartext.GetPtr(), op.cleartext.GetSize(), hash);
        CF_ASSERT(size == sizeof(hash), "Unexpected return size");
        ret = component::Digest(hash, sizeof(hash));
    }

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
