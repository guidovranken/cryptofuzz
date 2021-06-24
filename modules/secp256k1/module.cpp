#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>

extern "C" {
    #include <secp256k1.h>
    #include <secp256k1_recovery.h>
    #include <secp256k1_schnorrsig.h>
    #include <secp256k1_ecdh.h>
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

    std::optional<component::ECC_PublicKey> To_ECC_PublicKey(const secp256k1_context* ctx, const secp256k1_pubkey& pubkey) {
        std::optional<component::ECC_PublicKey> ret = std::nullopt;
        std::vector<uint8_t> pubkey_bytes(65);
        size_t pubkey_bytes_size = pubkey_bytes.size();

        CF_CHECK_EQ(secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes.data(), &pubkey_bytes_size, &pubkey, SECP256K1_FLAGS_TYPE_COMPRESSION), 1);
        CF_CHECK_EQ(pubkey_bytes_size, 65);

        {
            boost::multiprecision::cpp_int x, y;

            boost::multiprecision::import_bits(x, pubkey_bytes.begin() + 1, pubkey_bytes.begin() + 1 + 32);
            boost::multiprecision::import_bits(y, pubkey_bytes.begin() + 1 + 32, pubkey_bytes.end());

            ret = {secp256k1_detail::toString(x), secp256k1_detail::toString(y)};
        }

end:
        return ret;
    }

    bool PrivkeyToBytes(const component::ECC_PrivateKey& priv, uint8_t privkey_bytes[32]) {
        bool ret = false;

        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    priv.ToTrimmedString(),
                    privkey_bytes), true);

        ret = true;
end:
        return ret;
    }

    bool PubkeyToBytes(const component::ECC_PublicKey& pub, uint8_t pubkey_bytes[65]) {
        bool ret = false;

        pubkey_bytes[0] = 4;

        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    pub.first.ToTrimmedString(),
                    pubkey_bytes + 1), true);
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    pub.second.ToTrimmedString(),
                    pubkey_bytes + 1 + 32), true);
        ret = true;

end:
        return ret;
    }

    class Context {
        private:
            Datasource& ds;
            secp256k1_context* ctx = nullptr;
            void randomizeContext(void) {
                std::vector<uint8_t> seed;

                try {
                    if ( ds.Get<bool>() ) {
                        seed = ds.GetData(0, 32, 32);
                        CF_ASSERT(secp256k1_context_randomize(ctx, seed.data()) == 1, "Call to secp256k1_context_randomize failed");
                    }
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            }

        public:
            Context(Datasource& ds, const unsigned int flags) :
                ds(ds) {
                    CF_ASSERT((ctx = secp256k1_context_create(flags)) != nullptr, "Cannot create secp256k1 context");
            }
            ~Context(void) {
                CF_NORET(secp256k1_context_destroy(ctx));
                ctx = nullptr;
            }
            secp256k1_context* GetPtr(void) {
                randomizeContext();

                return ctx;
            }
    };


    std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(Datasource& ds, const std::string priv) {
        std::optional<component::ECC_PublicKey> ret = std::nullopt;
        secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
        secp256k1_pubkey pubkey;
        std::vector<uint8_t> pubkey_bytes(65);
        uint8_t key[32];

        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    priv,
                    key), true);
        CF_CHECK_EQ(secp256k1_ec_pubkey_create(ctx.GetPtr(), &pubkey, key), 1);

        ret = To_ECC_PublicKey(ctx.GetPtr(), pubkey);

end:
        return ret;
    }

    template <class T>
    void AssertZero(const T* v) {
        const static T nulls = {0};
        CF_ASSERT(memcmp(v, &nulls, sizeof(T)) == 0, "Variable is not all zeroes");
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

    static int nonce_function_schnorrsig(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo16, void *data) {
        (void)nonce32;
        (void)msg32;
        (void)key32;
        (void)xonly_pk32;
        (void)algo16;

        memcpy(nonce32, data, 32);

        return 1;
    }
}

std::optional<component::ECC_PublicKey> secp256k1::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    ret = secp256k1_detail::OpECC_PrivateToPublic(ds, op.priv.ToTrimmedString());

end:
    return ret;
}

std::optional<bool> secp256k1::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    uint8_t pubkey_bytes[65];
    pubkey_bytes[0] = 4;

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.pub.first.ToTrimmedString(),
                pubkey_bytes + 1), true);
    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.pub.second.ToTrimmedString(),
                pubkey_bytes + 1 + 32), true);

    ret = secp256k1_ec_pubkey_parse(ctx.GetPtr(), &pubkey, pubkey_bytes, sizeof(pubkey_bytes)) == 1;

end:
    return ret;
}

std::optional<component::ECDSA_Signature> secp256k1::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.UseRFC6979Nonce() == false && op.UseSpecifiedNonce() == false ) {
        return ret;
    }

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    std::vector<uint8_t> sig_bytes(64);
    std::vector<uint8_t> pubkey_bytes(65);
    size_t pubkey_bytes_size = pubkey_bytes.size();
    uint8_t key[32];
    uint8_t hash[32];
    uint8_t specified_nonce[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.priv.ToTrimmedString(),
                key), true);

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        const auto CT = op.cleartext.ECDSA_Pad(32);
        memcpy(hash, CT.GetPtr(), sizeof(hash));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        const auto _hash = crypto::sha256(op.cleartext.Get());
        memcpy(hash, _hash.data(), _hash.size());
    } else {
        goto end;
    }

    if ( op.UseRFC6979Nonce() == true ) {
        CF_CHECK_EQ(secp256k1_ecdsa_sign(ctx.GetPtr(), &sig, hash, key, secp256k1_nonce_function_rfc6979, nullptr), 1);
    } else if ( op.UseSpecifiedNonce() == true ) {
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.nonce.ToTrimmedString(),
                    specified_nonce), true);
        CF_CHECK_EQ(secp256k1_ecdsa_sign(ctx.GetPtr(), &sig, hash, key, secp256k1_detail::nonce_function, specified_nonce), 1);
    } else {
        CF_UNREACHABLE();
    }

    CF_CHECK_EQ(secp256k1_ecdsa_signature_serialize_compact(ctx.GetPtr(), sig_bytes.data(), &sig), 1);

    CF_CHECK_EQ(secp256k1_ec_pubkey_create(ctx.GetPtr(), &pubkey, key), 1);
    CF_CHECK_EQ(secp256k1_ec_pubkey_serialize(ctx.GetPtr(), pubkey_bytes.data(), &pubkey_bytes_size, &pubkey, SECP256K1_FLAGS_TYPE_COMPRESSION), 1);
    CF_CHECK_EQ(pubkey_bytes_size, 65);

    {
        boost::multiprecision::cpp_int r, s;

        auto component_pubkey = secp256k1_detail::OpECC_PrivateToPublic(ds, op.priv.ToTrimmedString());
        CF_CHECK_NE(component_pubkey, std::nullopt);

        boost::multiprecision::import_bits(r, sig_bytes.begin(), sig_bytes.begin() + 32);
        boost::multiprecision::import_bits(s, sig_bytes.begin() + 32, sig_bytes.end());

        ret = component::ECDSA_Signature(
                {secp256k1_detail::toString(r), secp256k1_detail::toString(s)},
                *component_pubkey);
    }

end:
    return ret;
}

std::optional<bool> secp256k1::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    uint8_t pubkey_bytes[65];
    uint8_t sig_bytes[64];
    uint8_t hash[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        const auto CT = op.cleartext.ECDSA_Pad(32);
        memcpy(hash, CT.GetPtr(), sizeof(hash));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        const auto _hash = crypto::sha256(op.cleartext.Get());
        memcpy(hash, _hash.data(), _hash.size());
    } else {
        goto end;
    }

    /* Beyond this point, a failure definitely means that the
     * pubkey or signature is invalid */
    ret = false;

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

    CF_CHECK_EQ(secp256k1_ec_pubkey_parse(ctx.GetPtr(), &pubkey, pubkey_bytes, sizeof(pubkey_bytes)), 1);
    CF_CHECK_EQ(secp256k1_ecdsa_signature_parse_compact(ctx.GetPtr(), &sig, sig_bytes), 1);
    /* ignore ret */ secp256k1_ecdsa_signature_normalize(ctx.GetPtr(), &sig, &sig);

    ret = secp256k1_ecdsa_verify(ctx.GetPtr(), &sig, hash, &pubkey) == 1 ? true : false;

end:
    return ret;
}

std::optional<component::ECC_PublicKey> secp256k1::OpECDSA_Recover(operation::ECDSA_Recover& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    uint8_t sig_bytes[64];
    uint8_t hash[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));
    CF_CHECK_LTE(op.id, 3);

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        const auto CT = op.cleartext.ECDSA_Pad(32);
        memcpy(hash, CT.GetPtr(), sizeof(hash));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        const auto _hash = crypto::sha256(op.cleartext.Get());
        memcpy(hash, _hash.data(), _hash.size());
    } else {
        goto end;
    }

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.first.ToTrimmedString(),
                sig_bytes), true);
    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.second.ToTrimmedString(),
                sig_bytes + 32), true);

    if ( secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.GetPtr(), &sig, sig_bytes, op.id) != 1 ) {
        /* https://github.com/bitcoin-core/secp256k1/blob/8ae56e33e749e16880dbfb4444fdae238b4426ac/src/modules/recovery/main_impl.h#L55 */
        secp256k1_detail::AssertZero<>(&sig);
        goto end;
    }

    if ( secp256k1_ecdsa_recover(ctx.GetPtr(), &pubkey, &sig, hash) == 1 ) {
        ret = secp256k1_detail::To_ECC_PublicKey(ctx.GetPtr(), pubkey);
    } else {
        /* https://github.com/bitcoin-core/secp256k1/blob/8ae56e33e749e16880dbfb4444fdae238b4426ac/src/modules/recovery/main_impl.h#L155 */
        secp256k1_detail::AssertZero<>(&pubkey);
    }

end:
    return ret;
}

std::optional<component::Schnorr_Signature> secp256k1::OpSchnorr_Sign(operation::Schnorr_Sign& op) {
    std::optional<component::Schnorr_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.UseBIP340Nonce() == false && op.UseSpecifiedNonce() == false ) {
        return ret;
    }

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
    secp256k1_xonly_pubkey pubkey;
    std::vector<uint8_t> sig_bytes(64);
    std::vector<uint8_t> pubkey_bytes(32);
    secp256k1_keypair keypair;
    uint8_t key[32];
    uint8_t hash[32];
    uint8_t specified_nonce[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.priv.ToTrimmedString(),
                key), true);

    CF_CHECK_EQ(secp256k1_keypair_create(ctx.GetPtr(), &keypair, key), 1);

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        CF_CHECK_EQ(op.cleartext.GetSize(), sizeof(hash));
        memcpy(hash, op.cleartext.GetPtr(), sizeof(hash));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        const auto _hash = crypto::sha256(op.cleartext.Get());
        memcpy(hash, _hash.data(), _hash.size());
    } else {
        goto end;
    }


    if ( op.UseBIP340Nonce() == true ) {
        CF_CHECK_EQ(secp256k1_schnorrsig_sign(ctx.GetPtr(), sig_bytes.data(), hash, &keypair, secp256k1_nonce_function_bip340, nullptr), 1);
    } else if ( op.UseSpecifiedNonce() == true ) {
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.nonce.ToTrimmedString(),
                    specified_nonce), true);
        CF_CHECK_EQ(secp256k1_schnorrsig_sign(ctx.GetPtr(), sig_bytes.data(), hash, &keypair, secp256k1_detail::nonce_function_schnorrsig, specified_nonce), 1);
    } else {
        CF_UNREACHABLE();
    }

    CF_CHECK_EQ(secp256k1_keypair_xonly_pub(ctx.GetPtr(), &pubkey, nullptr, &keypair), 1);
    CF_CHECK_EQ(secp256k1_xonly_pubkey_serialize(ctx.GetPtr(), pubkey_bytes.data(), &pubkey), 1);

    {
        boost::multiprecision::cpp_int x, r, s;

        boost::multiprecision::import_bits(x, pubkey_bytes.begin(), pubkey_bytes.end());
        boost::multiprecision::import_bits(r, sig_bytes.begin(), sig_bytes.begin() + 32);
        boost::multiprecision::import_bits(s, sig_bytes.begin() + 32, sig_bytes.end());

        ret = component::Schnorr_Signature(
                {secp256k1_detail::toString(r), secp256k1_detail::toString(s)},
                {secp256k1_detail::toString(x), "0"});
    }

end:
    return ret;
}

std::optional<bool> secp256k1::OpSchnorr_Verify(operation::Schnorr_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_xonly_pubkey pubkey;
    uint8_t pubkey_bytes[32];
    uint8_t sig_bytes[64];
    uint8_t hash[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        CF_CHECK_EQ(op.cleartext.GetSize(), sizeof(hash));
        memcpy(hash, op.cleartext.GetPtr(), sizeof(hash));
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        const auto _hash = crypto::sha256(op.cleartext.Get());
        memcpy(hash, _hash.data(), _hash.size());
    } else {
        goto end;
    }

    /* Beyond this point, a failure definitely means that the
     * pubkey or signature is invalid */
    ret = false;

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.pub.first.ToTrimmedString(),
                pubkey_bytes), true);

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.signature.first.ToTrimmedString(),
                sig_bytes), true);
    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.signature.signature.second.ToTrimmedString(),
                sig_bytes + 32), true);

    CF_CHECK_EQ(secp256k1_xonly_pubkey_parse(ctx.GetPtr(), &pubkey, pubkey_bytes), 1);

    ret = secp256k1_schnorrsig_verify(ctx.GetPtr(), sig_bytes, hash, &pubkey) == 1 ? true : false;

end:
    return ret;
}

std::optional<component::Secret> secp256k1::OpECDH_Derive(operation::ECDH_Derive& op) {
    std::optional<component::Secret> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    uint8_t privkey_bytes[32];
    uint8_t pubkey_bytes[65];
    uint8_t out[32];

    if ( op.curveType.Get(), CF_ECC_CURVE("secp256k1") ) {
        return ret;
    }

    memset(out, 0, 32);

    CF_CHECK_TRUE(secp256k1_detail::PrivkeyToBytes(op.priv, privkey_bytes));
    CF_CHECK_TRUE(secp256k1_detail::PubkeyToBytes(op.pub, pubkey_bytes));

    CF_CHECK_EQ(secp256k1_ec_pubkey_parse(ctx.GetPtr(), &pubkey, pubkey_bytes, sizeof(pubkey_bytes)), 1);

    CF_CHECK_EQ(secp256k1_ecdh(ctx.GetPtr(), out, &pubkey, privkey_bytes, nullptr, nullptr), 1);

end:
    ret = component::Secret(Buffer(out, sizeof(out)));

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
