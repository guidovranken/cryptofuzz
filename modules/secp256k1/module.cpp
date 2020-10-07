#include "module.h"
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <botan/hash.h>

extern "C" {
    #include <secp256k1.h>
}

namespace cryptofuzz {
namespace module {

secp256k1::secp256k1(void) :
    Module("secp256k1") { }

namespace secp256k1_detail {
    static bool EncodeBignum(const std::string s, uint8_t* out) {
        std::vector<uint8_t> v;
        boost::multiprecision::cpp_int c(s);
        boost::multiprecision::export_bits(c, std::back_inserter(v), 8);
        if ( v.size() > 32 ) {
            return false;
        }
        const auto diff = 32 - v.size();

        memset(out, 0, 32);
        memcpy(out + diff, v.data(), v.size());
        
        return true;
    }
}

std::optional<bool> secp256k1::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    secp256k1_context* ctx = nullptr;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    uint8_t pubkey_bytes[65];
    uint8_t sig_bytes[64];
    uint8_t hash[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));
    
    pubkey_bytes[0] = 4;
    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.pub.first.ToTrimmedString(),
                pubkey_bytes + 1), true);
    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.pub.second.ToTrimmedString(),
                pubkey_bytes + 1 + 32), true);

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.signature.first.ToTrimmedString(),
                sig_bytes), true);
    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.signature.second.ToTrimmedString(),
                sig_bytes + 32), true);

    {
        auto _hash = ::Botan::HashFunction::create("SHA-256");
        _hash->update(op.cleartext.GetPtr(), op.cleartext.GetSize());
        const auto CT = _hash->final();
        memcpy(hash, CT.data(), CT.size());
    }

    CF_CHECK_NE(ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), nullptr);

    CF_CHECK_EQ(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_bytes, sizeof(pubkey_bytes)), 1);
    CF_CHECK_EQ(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_bytes), 1);
    CF_CHECK_EQ(secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig), 1);

    ret = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubkey) == 1 ? true : false;

end:
    /* noret */ secp256k1_context_destroy(ctx);
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
