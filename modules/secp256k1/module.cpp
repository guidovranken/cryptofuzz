#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>

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

    static std::string toString(const boost::multiprecision::cpp_int& i) {
        std::stringstream ss;
        ss << i;

        if ( ss.str().empty() ) {
            return "0";
        } else {
            return ss.str();
        }
    }

    std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(const std::string priv) {
        std::optional<component::ECC_PublicKey> ret = std::nullopt;
        secp256k1_context* ctx = nullptr;
        secp256k1_pubkey pubkey;
        std::vector<uint8_t> pubkey_bytes(65);
        size_t pubkey_bytes_size = pubkey_bytes.size();
        uint8_t key[32];

        CF_CHECK_NE(ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN), nullptr);
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    priv,
                    key), true);
        CF_CHECK_EQ(secp256k1_ec_pubkey_create(ctx, &pubkey, key), 1);
        CF_CHECK_EQ(secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes.data(), &pubkey_bytes_size, &pubkey, SECP256K1_FLAGS_TYPE_COMPRESSION), 1);
        CF_CHECK_EQ(pubkey_bytes_size, 65);

        {
            boost::multiprecision::cpp_int x, y;

            boost::multiprecision::import_bits(x, pubkey_bytes.begin() + 1, pubkey_bytes.begin() + 1 + 32);
            boost::multiprecision::import_bits(y, pubkey_bytes.begin() + 1 + 32, pubkey_bytes.end());

            ret = {secp256k1_detail::toString(x), secp256k1_detail::toString(y)};
        }

end:
        /* noret */ secp256k1_context_destroy(ctx);
        return ret;
    }

    static int nonce_function(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
        (void)nonce32;
        (void)msg32;
        (void)key32;
        (void)algo16;
        (void)counter;

        memcpy(nonce32, data, 32);

        return counter == 0;
    }

}

std::optional<component::ECC_PublicKey> secp256k1::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    ret = secp256k1_detail::OpECC_PrivateToPublic(op.priv.ToTrimmedString());

end:
    return ret;
}

std::optional<component::ECDSA_Signature> secp256k1::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    if ( op.UseRFC6979Nonce() == false && op.UseSpecifiedNonce() == false ) {
        return ret;
    }

    secp256k1_context* ctx = nullptr;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    std::vector<uint8_t> sig_bytes(64);
    std::vector<uint8_t> pubkey_bytes(65);
    size_t pubkey_bytes_size = pubkey_bytes.size();
    uint8_t key[32];
    uint8_t hash[32];
    uint8_t specified_nonce[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    CF_CHECK_NE(ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN), nullptr);

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.priv.ToTrimmedString(),
                key), true);

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        CF_CHECK_EQ(op.cleartext.GetSize(), sizeof(hash));
        memcpy(hash, op.cleartext.GetPtr(), sizeof(hash));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        const auto _hash = crypto::sha256(op.cleartext.Get());
        memcpy(hash, _hash.data(), _hash.size());
    } else {
        goto end;
    }

    if ( op.UseRFC6979Nonce() == true ) {
        CF_CHECK_EQ(secp256k1_ecdsa_sign(ctx, &sig, hash, key, secp256k1_nonce_function_rfc6979, nullptr), 1);
    } else if ( op.UseSpecifiedNonce() == true ) {
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.nonce.ToTrimmedString(),
                    specified_nonce), true);
        CF_CHECK_EQ(secp256k1_ecdsa_sign(ctx, &sig, hash, key, secp256k1_detail::nonce_function, specified_nonce), 1);
    } else {
        abort();
    }

    CF_CHECK_EQ(secp256k1_ecdsa_signature_serialize_compact(ctx, sig_bytes.data(), &sig), 1);

    CF_CHECK_EQ(secp256k1_ec_pubkey_create(ctx, &pubkey, key), 1);
    CF_CHECK_EQ(secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes.data(), &pubkey_bytes_size, &pubkey, SECP256K1_FLAGS_TYPE_COMPRESSION), 1);
    CF_CHECK_EQ(pubkey_bytes_size, 65);

    {
        boost::multiprecision::cpp_int r, s;

        auto component_pubkey = secp256k1_detail::OpECC_PrivateToPublic(op.priv.ToTrimmedString());
        CF_CHECK_NE(component_pubkey, std::nullopt);

        boost::multiprecision::import_bits(r, sig_bytes.begin(), sig_bytes.begin() + 32);
        boost::multiprecision::import_bits(s, sig_bytes.begin() + 32, sig_bytes.end());

        ret = component::ECDSA_Signature(
                {secp256k1_detail::toString(r), secp256k1_detail::toString(s)},
                *component_pubkey);
    }

end:
    /* noret */ secp256k1_context_destroy(ctx);
    return ret;
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

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        CF_CHECK_EQ(op.cleartext.GetSize(), sizeof(hash));
        memcpy(hash, op.cleartext.GetPtr(), sizeof(hash));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        const auto _hash = crypto::sha256(op.cleartext.Get());
        memcpy(hash, _hash.data(), _hash.size());
    } else {
        goto end;
    }

    CF_CHECK_NE(ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY), nullptr);

    CF_CHECK_EQ(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkey_bytes, sizeof(pubkey_bytes)), 1);
    CF_CHECK_EQ(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_bytes), 1);
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

    ret = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubkey) == 1 ? true : false;

end:
    /* noret */ secp256k1_context_destroy(ctx);
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
