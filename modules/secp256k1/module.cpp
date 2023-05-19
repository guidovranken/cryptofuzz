#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <sstream>

extern "C" {
    #include <secp256k1.h>
    #include <secp256k1_recovery.h>
#if \
    !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
    !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
    !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
    #include <secp256k1_schnorrsig.h>
#endif
    #include <secp256k1_ecdh.h>
    #include "secp256k1_api.h"
}

namespace cryptofuzz {
namespace module {

secp256k1::secp256k1(void) :
    Module("secp256k1") { }

namespace secp256k1_detail {
    static int CheckRet(const int ret) {
        CF_ASSERT(ret == 0 || ret == 1, "Unexpected return value");

        return ret;
    }

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

    std::optional<component::ECC_PublicKey> To_ECC_PublicKey(const secp256k1_context* ctx, const secp256k1_pubkey* pubkey) {
        std::optional<component::ECC_PublicKey> ret = std::nullopt;
        std::vector<uint8_t> pubkey_bytes(65);
        size_t pubkey_bytes_size = pubkey_bytes.size();

        CF_CHECK_EQ(
                CheckRet(secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes.data(), &pubkey_bytes_size, pubkey, SECP256K1_FLAGS_TYPE_COMPRESSION)), 1);
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

    template <class T>
    void AssertZero(const T* v) {
        const static T nulls = {0};
        CF_ASSERT(memcmp(v, &nulls, sizeof(T)) == 0, "Variable is not all zeroes");
    }

    class Context {
        private:
            Datasource& ds;
            secp256k1_context* ctx = nullptr;
            void randomizeContext(void) {
#if !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
    !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
                std::vector<uint8_t> seed;

                try {
                    if ( ds.Get<bool>() ) {
                        seed = ds.GetData(0, 32, 32);
                        CF_ASSERT(
                                CheckRet(secp256k1_context_randomize(ctx, seed.data())) == 1,
                                "Call to secp256k1_context_randomize failed");
                    }
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
#endif
            }

            void clone(void) {
                const auto newCtx = secp256k1_context_clone(ctx);
                CF_ASSERT(newCtx != nullptr, "secp256k1_context_clone failed");
                CF_NORET(secp256k1_context_destroy(ctx));
                ctx = newCtx;
            }

        public:
            Context(Datasource& ds, const unsigned int flags) :
                ds(ds) {
                    CF_ASSERT((ctx = secp256k1_context_create(flags)) != nullptr, "Cannot create secp256k1 context");
            }
            ~Context(void) {
                GetPtr();

                CF_NORET(secp256k1_context_destroy(ctx));
                ctx = nullptr;
            }
            secp256k1_context* GetPtr(void) {
                try {
                    if ( ds.Get<bool>() ) {
                        randomizeContext();
                    }

                    if ( ds.Get<bool>() ) {
                        clone();
                    }
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                return ctx;
            }
            secp256k1_context* GetPtrDirect(void) {
                return ctx;
            }
    };

    class ECDSA_Recoverable_Signature {
        private:
            Datasource& ds;
            Context& ctx;
            bool initialized = false;
            secp256k1_ecdsa_recoverable_signature* sig = nullptr;

            void serializeCompact(void) {
                uint8_t data[64];

                int id;

                if ( CheckRet(secp256k1_ecdsa_recoverable_signature_serialize_compact(
                            ctx.GetPtr(),
                            data,
                            &id,
                            sig)) == 1 ) {
                    CF_ASSERT(
                            CheckRet(secp256k1_ecdsa_recoverable_signature_parse_compact(
                                ctx.GetPtr(),
                                sig,
                                data,
                                id)) == 1,
                            "Cannot deserialize compact recoverable signature");
                }
            }

            void convert(void) {
                secp256k1_ecdsa_signature sig_;
                CheckRet(secp256k1_ecdsa_recoverable_signature_convert(ctx.GetPtr(), &sig_, sig));
            }
        public:
            ECDSA_Recoverable_Signature(Datasource& ds, Context& ctx) :
                ds(ds), ctx(ctx) {
                sig = static_cast<secp256k1_ecdsa_recoverable_signature*>(malloc(sizeof(secp256k1_ecdsa_recoverable_signature)));
            }
            ~ECDSA_Recoverable_Signature(void) {
                GetPtr();

                free(sig);
                sig = nullptr;
            }
            void SetInitialized(void) {
                initialized = true;
            }
            secp256k1_ecdsa_recoverable_signature* GetPtr() {
                if ( initialized == true ) {
                    try {
                        if ( ds.Get<bool>() ) {
                            serializeCompact();
                        }

                        if ( ds.Get<bool>() ) {
                            convert();
                        }
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }
                return sig;
            }

            secp256k1_ecdsa_recoverable_signature* GetPtrDirect(void) const {
                return sig;
            }

            bool ParseCompact(const uint8_t* data, const uint8_t id) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto sigPtr = GetPtr();

                const bool ret = CheckRet(secp256k1_ecdsa_recoverable_signature_parse_compact(ctxPtr, sigPtr, data, id)) == 1;

                if ( ret ) {
                    SetInitialized();
                } else {
                    /* https://github.com/bitcoin-core/secp256k1/blob/8ae56e33e749e16880dbfb4444fdae238b4426ac/src/modules/recovery/main_impl.h#L55 */
                    secp256k1_detail::AssertZero<>(sigPtr);
                }

                return ret;
            }
    };

    class Pubkey {
        private:
            Datasource& ds;
            Context& ctx;
            bool initialized = false;
            secp256k1_pubkey* pub = nullptr;

            void serialize(void) {
                uint8_t* data = nullptr;
                size_t original_size = 0;
                try {
                    original_size = ds.Get<uint16_t>();
                    size_t size = original_size;
                    data = util::malloc(size);

                    if ( data != nullptr ) {
                        unsigned int flags = SECP256K1_FLAGS_TYPE_COMPRESSION;
                        if ( ds.Get<bool>() ) {
                            flags |= SECP256K1_FLAGS_BIT_COMPRESSION;
                        }

                        bool validOutsize;

                        if ( flags & SECP256K1_FLAGS_BIT_COMPRESSION ) {
                            validOutsize = size >= 33;
                        } else {
                            validOutsize = size >= 65;
                        }

                        if ( validOutsize ) {
                            if (
                                CheckRet(secp256k1_ec_pubkey_serialize(
                                        ctx.GetPtr(),
                                        data,
                                        &size,
                                        pub,
                                        flags)) == 1 ) {
                                CF_ASSERT(
                                        CheckRet(secp256k1_ec_pubkey_parse(
                                            ctx.GetPtr(),
                                            pub,
                                            data,
                                            size)) == 1,
                                        "Cannot deserialize pubkey");
                            }
                        }
                    }
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( original_size > 0 ) {
                    util::free(data);
                }
            }
        public:
            Pubkey(Datasource& ds, Context& ctx) :
                ds(ds), ctx(ctx) {
                pub = static_cast<secp256k1_pubkey*>(malloc(sizeof(secp256k1_pubkey)));
            }
            ~Pubkey(void) {
                GetPtr();

                free(pub);
                pub = nullptr;
            }
            void SetInitialized(void) {
                initialized = true;
            }
            secp256k1_pubkey* GetPtr() {
                return pub;
                if ( initialized == true ) {
                    try {
                        if ( ds.Get<bool>() ) {
                            serialize();
                        }
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }
                return pub;
            }
            bool Create(const uint8_t key[32]) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto pubPtr = GetPtr();

                const bool ret = CheckRet(secp256k1_ec_pubkey_create(ctxPtr, pubPtr, key)) == 1;

                if ( ret ) {
                    SetInitialized();
                }

                return ret;
            }

            bool Serialize(uint8_t* data, size_t* size) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto pubPtr = GetPtr();

                const bool ret = CheckRet(secp256k1_ec_pubkey_serialize(ctxPtr, data, size, pubPtr, SECP256K1_FLAGS_TYPE_COMPRESSION)) == 1;

                if ( ret ) {
                    CF_ASSERT(*size == 65, "Serialized pubkey is not 65 bytes");
                }

                return ret;
            }

            bool Parse(const uint8_t* data, size_t size) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto pubPtr = GetPtr();

                const bool ret = CheckRet(secp256k1_ec_pubkey_parse(ctxPtr, pubPtr, data, size)) == 1;

                if ( ret ) {
                    SetInitialized();
                }

                return ret;
            }

#if !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
            bool ECDH(uint8_t out[32], const uint8_t key[32]) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto pubPtr = GetPtr();

                return CheckRet(secp256k1_ecdh(ctxPtr, out, pubPtr, key, nullptr, nullptr)) == 1;
            }
#endif

            bool Recover(ECDSA_Recoverable_Signature& sig, const uint8_t hash[32]) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto sigPtr = sig.GetPtrDirect();
                const auto pubPtr = GetPtr();

                const bool ret = CheckRet(secp256k1_ecdsa_recover(ctxPtr, pubPtr, sigPtr, hash)) == 1;

                if ( ret == true ) {
                    SetInitialized();
                } else {
                    /* https://github.com/bitcoin-core/secp256k1/blob/8ae56e33e749e16880dbfb4444fdae238b4426ac/src/modules/recovery/main_impl.h#L155 */
                    AssertZero<>(pubPtr);
                }

                return ret;
            }

            secp256k1_pubkey* GetPtrDirect(void) const {
                return pub;
            }
    };

    class ECDSA_Signature {
        private:
            Datasource& ds;
            Context& ctx;
            bool initialized = false;
            secp256k1_ecdsa_signature* sig = nullptr;

            void serializeDER(void) {
                const size_t original_size = ds.Get<uint16_t>();
                size_t size = original_size;
                uint8_t* data = util::malloc(size);

                if ( data != nullptr ) {
                    if ( CheckRet(secp256k1_ecdsa_signature_serialize_der(
                                ctx.GetPtr(),
                                data,
                                &size,
                                sig)) == 1 ) {
                        CF_ASSERT(
                                CheckRet(secp256k1_ecdsa_signature_parse_der(
                                    ctx.GetPtr(),
                                    sig,
                                    data,
                                    size)) == 1,
                                "Cannot deserialize DER signature");
                    }
                }

                if ( original_size > 0 ) {
                    util::free(data);
                }
            }

            void serializeCompact(void) {
                uint8_t data[64];

                if ( CheckRet(secp256k1_ecdsa_signature_serialize_compact(
                            ctx.GetPtr(),
                            data,
                            sig)) == 1 ) {
                    CF_ASSERT(
                            CheckRet(secp256k1_ecdsa_signature_parse_compact(
                                ctx.GetPtr(),
                                sig,
                                data)) == 1,
                            "Cannot deserialize compact signature");
                }
            }
        public:
            ECDSA_Signature(Datasource& ds, Context& ctx) :
                ds(ds), ctx(ctx) {
                sig = static_cast<secp256k1_ecdsa_signature*>(malloc(sizeof(secp256k1_ecdsa_signature)));
            }
            ~ECDSA_Signature(void) {
                GetPtr();

                free(sig);
                sig = nullptr;
            }
            void SetInitialized(void) {
                initialized = true;
            }
            secp256k1_ecdsa_signature* GetPtr() {
                if ( initialized == true ) {
                    try {
                        if ( ds.Get<bool>() ) {
                            serializeDER();
                        }

                        if ( ds.Get<bool>() ) {
                            serializeCompact();
                        }
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }
                return sig;
            }

            bool ParseCompact(const uint8_t* data) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto sigPtr = GetPtr();

                const bool ret = CheckRet(secp256k1_ecdsa_signature_parse_compact(ctxPtr, sigPtr, data)) == 1;

                if ( ret ) {
                    SetInitialized();
                }

                return ret;
            }

            void Normalize(void) {
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto sigPtr = GetPtr();

                /* ignore ret */ CheckRet(secp256k1_ecdsa_signature_normalize(ctxPtr, sigPtr, sigPtr));
            }

            bool Verify(const uint8_t hash[32], Pubkey& pub) {
                const auto sigPtr = GetPtr();
                const auto ctxPtr = ctx.GetPtrDirect();
                const auto pubPtr = pub.GetPtrDirect();

                return CheckRet(secp256k1_ecdsa_verify(ctxPtr, sigPtr, hash, pubPtr)) == 1;
            }
    };

    std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(Datasource& ds, const std::string priv) {
        std::optional<component::ECC_PublicKey> ret = std::nullopt;
        secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
        secp256k1_detail::Pubkey pub(ds, ctx);
        std::vector<uint8_t> pubkey_bytes(65);
        uint8_t key[32];

        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    priv,
                    key), true);
        CF_CHECK_TRUE(pub.Create(key));

        {
            const auto ctxPtr = ctx.GetPtrDirect();
            const auto pubPtr = pub.GetPtr();

            ret = To_ECC_PublicKey(ctxPtr, pubPtr);
        }

end:
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

#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
    static int nonce_function_schnorrsig(
            unsigned char *nonce32,
            const unsigned char *msg,
            size_t msglen,
            const unsigned char *key32,
            const unsigned char *xonly_pk32,
            const unsigned char *algo,
            size_t algolen,
            void *data) {
        (void)nonce32;
        (void)msg;
        (void)msglen;
        (void)key32;
        (void)xonly_pk32;
        (void)algo;
        (void)algolen;

        memcpy(nonce32, data, 32);

        return 1;
    }
#endif
}

std::optional<component::ECC_PublicKey> secp256k1::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    ret = secp256k1_detail::OpECC_PrivateToPublic(ds, op.priv.ToTrimmedString());

end:
    util::UnsetGlobalDs();

    return ret;
}

std::optional<bool> secp256k1::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_detail::Pubkey pub(ds, ctx);
    uint8_t pubkey_bytes[65];
    pubkey_bytes[0] = 4;

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.pub.first.ToTrimmedString(),
                pubkey_bytes + 1), true);
    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.pub.second.ToTrimmedString(),
                pubkey_bytes + 1 + 32), true);

    ret = pub.Parse(pubkey_bytes, sizeof(pubkey_bytes));

end:
    util::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECDSA_Signature> secp256k1::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
    secp256k1_detail::Pubkey pub(ds, ctx);
    secp256k1_detail::ECDSA_Signature sig(ds, ctx);
    std::vector<uint8_t> sig_bytes(64);
    std::vector<uint8_t> pubkey_bytes(65);
    size_t pubkey_bytes_size = pubkey_bytes.size();
    uint8_t key[32];
    uint8_t hash[32];
    uint8_t specified_nonce[32];

    CF_CHECK_TRUE(op.UseRFC6979Nonce() || op.UseSpecifiedNonce());

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
        CF_CHECK_EQ(secp256k1_ecdsa_sign(ctx.GetPtr(), sig.GetPtr(), hash, key, secp256k1_nonce_function_rfc6979, nullptr), 1);
        sig.SetInitialized();
    } else if ( op.UseSpecifiedNonce() == true ) {
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.nonce.ToTrimmedString(),
                    specified_nonce), true);
        CF_CHECK_EQ(secp256k1_ecdsa_sign(ctx.GetPtr(), sig.GetPtr(), hash, key, secp256k1_detail::nonce_function, specified_nonce), 1);
        sig.SetInitialized();
    } else {
        CF_UNREACHABLE();
    }

    CF_CHECK_EQ(secp256k1_ecdsa_signature_serialize_compact(ctx.GetPtr(), sig_bytes.data(), sig.GetPtr()), 1);

    CF_CHECK_TRUE(pub.Create(key));
    CF_CHECK_TRUE(pub.Serialize(pubkey_bytes.data(), &pubkey_bytes_size));

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
    util::UnsetGlobalDs();

    return ret;
}

std::optional<bool> secp256k1::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_detail::Pubkey pub(ds, ctx);
    secp256k1_detail::ECDSA_Signature sig(ds, ctx);
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

    CF_CHECK_TRUE(pub.Parse(pubkey_bytes, sizeof(pubkey_bytes)));

    CF_CHECK_TRUE(sig.ParseCompact(sig_bytes));
    sig.Normalize();

    ret = sig.Verify(hash, pub);

end:
    util::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECC_PublicKey> secp256k1::OpECDSA_Recover(operation::ECDSA_Recover& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_detail::Pubkey pub(ds, ctx);
    secp256k1_detail::ECDSA_Recoverable_Signature sig(ds, ctx);
    uint8_t sig_bytes[64];
    uint8_t hash[32];
    std::vector<uint8_t> pubkey_bytes(65);
    size_t pubkey_bytes_size = pubkey_bytes.size();

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

    CF_CHECK_TRUE(sig.ParseCompact(sig_bytes, op.id));

    CF_CHECK_TRUE(pub.Recover(sig, hash));
    CF_CHECK_TRUE(pub.Serialize(pubkey_bytes.data(), &pubkey_bytes_size));

    {
        boost::multiprecision::cpp_int x, y;

        boost::multiprecision::import_bits(x, pubkey_bytes.begin() + 1, pubkey_bytes.begin() + 33);
        boost::multiprecision::import_bits(y, pubkey_bytes.begin() + 33, pubkey_bytes.end());

        ret = component::ECC_PublicKey(secp256k1_detail::toString(x), secp256k1_detail::toString(y));
    }

end:
    util::UnsetGlobalDs();

    return ret;
}

#if \
        !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
        !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
        !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
        !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
std::optional<component::Schnorr_Signature> secp256k1::OpSchnorr_Sign(operation::Schnorr_Sign& op) {
    std::optional<component::Schnorr_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
    secp256k1_xonly_pubkey pubkey;
    std::vector<uint8_t> sig_bytes(64);
    std::vector<uint8_t> pubkey_bytes(32);
    secp256k1_keypair keypair;
    uint8_t key[32];
    Buffer input;
    uint8_t specified_nonce[32];
    secp256k1_schnorrsig_extraparams extraparams;

    CF_CHECK_TRUE(op.UseBIP340Nonce() || op.UseSpecifiedNonce() );

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                op.priv.ToTrimmedString(),
                key), true);

    CF_CHECK_EQ(secp256k1_keypair_create(ctx.GetPtr(), &keypair, key), 1);

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        input = op.cleartext;
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        input = op.cleartext.SHA256();
    } else {
        goto end;
    }

    if ( op.UseBIP340Nonce() == true ) {
        extraparams.noncefp = secp256k1_nonce_function_bip340;
        extraparams.ndata = nullptr;
    } else if ( op.UseSpecifiedNonce() == true ) {
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.nonce.ToTrimmedString(),
                    specified_nonce), true);
        extraparams.noncefp = secp256k1_detail::nonce_function_schnorrsig;
        extraparams.ndata = specified_nonce;
    } else {
        CF_UNREACHABLE();
    }

    /* Manually set magic until this is fixed:
     * https://github.com/bitcoin-core/secp256k1/issues/962
     */
    extraparams.magic[0] = 0xDA;
    extraparams.magic[1] = 0x6F;
    extraparams.magic[2] = 0xB3;
    extraparams.magic[3] = 0x8C;

    CF_CHECK_EQ(
            secp256k1_detail::CheckRet(
                secp256k1_schnorrsig_sign_custom(ctx.GetPtr(), sig_bytes.data(), input.GetPtr(), input.GetSize(), &keypair, &extraparams)
        ), 1);

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
    util::UnsetGlobalDs();

    return ret;
}

std::optional<bool> secp256k1::OpSchnorr_Verify(operation::Schnorr_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_VERIFY);
    secp256k1_xonly_pubkey pubkey;
    uint8_t pubkey_bytes[32];
    uint8_t sig_bytes[64];
    Buffer input;

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        input = op.cleartext;
    } else if ( op.digestType.Get() == CF_DIGEST("SHA256") ) {
        input = op.cleartext.SHA256();
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

    ret = secp256k1_detail::CheckRet(
            secp256k1_schnorrsig_verify(ctx.GetPtr(), sig_bytes, input.GetPtr(), input.GetSize(), &pubkey)
            ) == 1 ? true : false;

end:
    util::UnsetGlobalDs();

    return ret;
}
#endif

#if !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
std::optional<component::Secret> secp256k1::OpECDH_Derive(operation::ECDH_Derive& op) {
    std::optional<component::Secret> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    util::SetGlobalDs(&ds);

    secp256k1_detail::Context ctx(ds, SECP256K1_CONTEXT_SIGN);
    secp256k1_detail::Pubkey pub(ds, ctx);
    uint8_t privkey_bytes[32];
    uint8_t pubkey_bytes[65];
    uint8_t out[32];

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    memset(out, 0, 32);

    CF_CHECK_TRUE(secp256k1_detail::PrivkeyToBytes(op.priv, privkey_bytes));
    CF_CHECK_TRUE(secp256k1_detail::PubkeyToBytes(op.pub, pubkey_bytes));

    CF_CHECK_TRUE(pub.Parse(pubkey_bytes, sizeof(pubkey_bytes)));

    CF_CHECK_TRUE(pub.ECDH(out, privkey_bytes));

#if !defined(CRYPTOFUZZ_DISABLE_SPECIAL_ECDH)
    ret = component::Secret(Buffer(out, sizeof(out)));
#endif

end:
    util::UnsetGlobalDs();
    return ret;
}
#endif

namespace secp256k1_detail {
    bool ToScalar(void* scalar, const component::Bignum& bn) {
        bool ret = false;
        std::optional<std::vector<uint8_t>> bin;
        int overflow;

        CF_CHECK_NE(bin = util::DecToBin(bn.ToTrimmedString(), 32), std::nullopt);
        CF_NORET(cryptofuzz_secp256k1_scalar_set_b32(scalar, bin->data(), &overflow));
        CF_CHECK_EQ(overflow, 0);

        ret = true;
end:
        return ret;
    }

    bool ToFe(void* fe, const component::Bignum& bn) {
        bool ret = false;
        std::optional<std::vector<uint8_t>> bin;

        CF_CHECK_NE(bin = util::DecToBin(bn.ToTrimmedString(), 32), std::nullopt);
        CF_CHECK_EQ(cryptofuzz_secp256k1_fe_set_b32_limit(fe, bin->data()), 1);

        ret = true;
end:
        return ret;
    }

    std::optional<component::Bignum> ToComponentBignum_scalar(const void* scalar) {
        std::optional<component::Bignum> ret = std::nullopt;

        uint8_t scalar_bytes[32];

        CF_NORET(cryptofuzz_secp256k1_scalar_get_b32(scalar_bytes, scalar));

        ret = component::Bignum(util::BinToDec(scalar_bytes, sizeof(scalar_bytes)));

        return ret;
    }

    std::optional<component::Bignum> ToComponentBignum_fe(fuzzing::datasource::Datasource& ds, void* fe) {
        std::optional<component::Bignum> ret = std::nullopt;

        uint8_t fe_bytes[32];

        bool var = false;
        try { var = ds.Get<bool>(); } catch ( ... ) { }

        CF_NORET(cryptofuzz_secp256k1_fe_get_b32(fe_bytes, fe, var ? 1 : 0));

        ret = component::Bignum(util::BinToDec(fe_bytes, sizeof(fe_bytes)));

        return ret;
    }
}

std::optional<component::ECC_Point> secp256k1::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    void* a_ge = util::malloc(cryptofuzz_secp256k1_ge_size());
    void* b_ge = util::malloc(cryptofuzz_secp256k1_ge_size());
    void* res_ge = util::malloc(cryptofuzz_secp256k1_ge_size());

    void* a_gej = util::malloc(cryptofuzz_secp256k1_gej_size());
    void* b_gej = util::malloc(cryptofuzz_secp256k1_gej_size());
    void* res_gej = util::malloc(cryptofuzz_secp256k1_gej_size());

    {
        uint8_t point_bytes[65];
        point_bytes[0] = 4;
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.first.ToTrimmedString(),
                    point_bytes + 1), true);
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.second.ToTrimmedString(),
                    point_bytes + 1 + 32), true);

        CF_CHECK_EQ(
                secp256k1_detail::CheckRet(
                    cryptofuzz_secp256k1_eckey_pubkey_parse(a_ge, point_bytes, sizeof(point_bytes))
                ), 1);
    }

    {
        uint8_t point_bytes[65];
        point_bytes[0] = 4;
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.b.first.ToTrimmedString(),
                    point_bytes + 1), true);
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.b.second.ToTrimmedString(),
                    point_bytes + 1 + 32), true);

        CF_CHECK_EQ(
                secp256k1_detail::CheckRet(
                    cryptofuzz_secp256k1_eckey_pubkey_parse(b_ge, point_bytes, sizeof(point_bytes))
                ), 1);
    }

    CF_NORET(cryptofuzz_secp256k1_gej_set_ge(a_gej, a_ge));
    CF_NORET(cryptofuzz_secp256k1_gej_set_ge(b_gej, b_ge));

    {
        bool var = false;
        try { var = ds.Get<bool>(); } catch ( ... ) { }

        if ( var == false ) {
            CF_NORET(cryptofuzz_secp256k1_gej_add_ge(res_gej, a_gej, b_gej));
        } else {
            CF_NORET(cryptofuzz_secp256k1_gej_add_ge_var(res_gej, a_gej, b_ge, nullptr));
        }
    }

    CF_NORET(cryptofuzz_secp256k1_ge_set_gej(res_ge, res_gej));

    {
        std::vector<uint8_t> point_bytes(65);
        size_t point_bytes_size = point_bytes.size();
        CF_CHECK_EQ(
                secp256k1_detail::CheckRet(
                    cryptofuzz_secp256k1_eckey_pubkey_serialize(res_ge, point_bytes.data(), &point_bytes_size, 0)
                    ), 1);

        {
            boost::multiprecision::cpp_int x, y;

            boost::multiprecision::import_bits(x, point_bytes.begin() + 1, point_bytes.begin() + 1 + 32);
            boost::multiprecision::import_bits(y, point_bytes.begin() + 1 + 32, point_bytes.end());

            ret = {secp256k1_detail::toString(x), secp256k1_detail::toString(y)};
        }
    }

end:
    util::free(a_ge);
    util::free(b_ge);
    util::free(res_ge);

    util::free(a_gej);
    util::free(b_gej);
    util::free(res_gej);

    return ret;
}

std::optional<component::ECC_Point> secp256k1::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    void* a_ge = util::malloc(cryptofuzz_secp256k1_ge_size());
    void* b = util::malloc(cryptofuzz_secp256k1_scalar_type_size());
    void* res_ge = util::malloc(cryptofuzz_secp256k1_ge_size());

    void* a_gej = util::malloc(cryptofuzz_secp256k1_gej_size());
    void* res_gej = util::malloc(cryptofuzz_secp256k1_gej_size());

    {
        uint8_t point_bytes[65];
        point_bytes[0] = 4;
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.first.ToTrimmedString(),
                    point_bytes + 1), true);
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.second.ToTrimmedString(),
                    point_bytes + 1 + 32), true);

        CF_CHECK_EQ(cryptofuzz_secp256k1_eckey_pubkey_parse(a_ge, point_bytes, sizeof(point_bytes)), 1);
    }

    CF_CHECK_TRUE(secp256k1_detail::ToScalar(b, op.b));

    CF_NORET(cryptofuzz_secp256k1_gej_set_ge(a_gej, a_ge));

#if \
    !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
    !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
    !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
    CF_NORET(cryptofuzz_secp256k1_ecmult(res_gej, a_gej, b, nullptr));
#else
    /* TODO */
    goto end;
#endif

    CF_NORET(cryptofuzz_secp256k1_ge_set_gej(res_ge, res_gej));

    {
        std::vector<uint8_t> point_bytes(65);
        size_t point_bytes_size = point_bytes.size();
        {
            const bool ok = cryptofuzz_secp256k1_eckey_pubkey_serialize(res_ge, point_bytes.data(), &point_bytes_size, 0) == 1;
            if ( cryptofuzz_secp256k1_scalar_is_zero(b) ) {
                CF_ASSERT(ok == false, "Point multiplication by 0 does not yield point at infinity");
                goto end;
            }

            CF_ASSERT(ok == true, "Point multiplication of valid point yields invalid point");
        }

        {
            boost::multiprecision::cpp_int x, y;

            boost::multiprecision::import_bits(x, point_bytes.begin() + 1, point_bytes.begin() + 1 + 32);
            boost::multiprecision::import_bits(y, point_bytes.begin() + 1 + 32, point_bytes.end());

            ret = {secp256k1_detail::toString(x), secp256k1_detail::toString(y)};
        }
    }

end:
    util::free(a_ge);
    util::free(b);
    util::free(res_ge);

    util::free(a_gej);
    util::free(res_gej);

    return ret;
}

std::optional<component::ECC_Point> secp256k1::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    void* a_ge = util::malloc(cryptofuzz_secp256k1_ge_size());
    void* res_ge = util::malloc(cryptofuzz_secp256k1_ge_size());

    void* a_gej = util::malloc(cryptofuzz_secp256k1_gej_size());
    void* res_gej = util::malloc(cryptofuzz_secp256k1_gej_size());

    {
        uint8_t point_bytes[65];
        point_bytes[0] = 4;
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.first.ToTrimmedString(),
                    point_bytes + 1), true);
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.second.ToTrimmedString(),
                    point_bytes + 1 + 32), true);

        CF_CHECK_EQ(
                secp256k1_detail::CheckRet(
                    cryptofuzz_secp256k1_eckey_pubkey_parse(a_ge, point_bytes, sizeof(point_bytes))
                ), 1);
    }

    CF_NORET(cryptofuzz_secp256k1_gej_set_ge(a_gej, a_ge));

    CF_NORET(cryptofuzz_secp256k1_gej_neg(res_gej, a_gej));

    CF_NORET(cryptofuzz_secp256k1_ge_set_gej(res_ge, res_gej));

    {
        std::vector<uint8_t> point_bytes(65);
        size_t point_bytes_size = point_bytes.size();

        {
            const bool ok = secp256k1_detail::CheckRet(
                    cryptofuzz_secp256k1_eckey_pubkey_serialize(res_ge, point_bytes.data(), &point_bytes_size, 0)
                    ) == 1;
            CF_ASSERT(ok, "Negation of valid point yields invalid point");
        }

        {
            boost::multiprecision::cpp_int x, y;

            boost::multiprecision::import_bits(x, point_bytes.begin() + 1, point_bytes.begin() + 1 + 32);
            boost::multiprecision::import_bits(y, point_bytes.begin() + 1 + 32, point_bytes.end());

            ret = {secp256k1_detail::toString(x), secp256k1_detail::toString(y)};
        }
    }

end:
    util::free(a_ge);
    util::free(res_ge);

    util::free(a_gej);
    util::free(res_gej);

    return ret;
}

std::optional<component::ECC_Point> secp256k1::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    if ( !op.curveType.Is(CF_ECC_CURVE("secp256k1")) ) {
        return ret;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    void* a_ge = util::malloc(cryptofuzz_secp256k1_ge_size());
    void* res_ge = util::malloc(cryptofuzz_secp256k1_ge_size());

    void* a_gej = util::malloc(cryptofuzz_secp256k1_gej_size());
    void* res_gej = util::malloc(cryptofuzz_secp256k1_gej_size());

    {
        uint8_t point_bytes[65];
        point_bytes[0] = 4;
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.first.ToTrimmedString(),
                    point_bytes + 1), true);
        CF_CHECK_EQ(secp256k1_detail::EncodeBignum(
                    op.a.second.ToTrimmedString(),
                    point_bytes + 1 + 32), true);

        CF_CHECK_EQ(
                secp256k1_detail::CheckRet(
                    cryptofuzz_secp256k1_eckey_pubkey_parse(a_ge, point_bytes, sizeof(point_bytes))
                ), 1);
    }

    CF_NORET(cryptofuzz_secp256k1_gej_set_ge(a_gej, a_ge));

    {
        bool var = false;
        try { var = ds.Get<bool>(); } catch ( ... ) { }

#if \
    !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
    !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
    !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
        if ( var == false ) {
            CF_NORET(cryptofuzz_secp256k1_gej_double(res_gej, a_gej));
        } else {
            CF_NORET(cryptofuzz_secp256k1_gej_double_var(res_gej, a_gej, nullptr));
        }
#else
        CF_NORET(cryptofuzz_secp256k1_gej_double_var(res_gej, a_gej, nullptr));
#endif
    }

    CF_NORET(cryptofuzz_secp256k1_ge_set_gej(res_ge, res_gej));

    {
        std::vector<uint8_t> point_bytes(65);
        size_t point_bytes_size = point_bytes.size();
        CF_CHECK_EQ(
                secp256k1_detail::CheckRet(
                    cryptofuzz_secp256k1_eckey_pubkey_serialize(res_ge, point_bytes.data(), &point_bytes_size, 0)
                    ), 1);

        {
            boost::multiprecision::cpp_int x, y;

            boost::multiprecision::import_bits(x, point_bytes.begin() + 1, point_bytes.begin() + 1 + 32);
            boost::multiprecision::import_bits(y, point_bytes.begin() + 1 + 32, point_bytes.end());

            ret = {secp256k1_detail::toString(x), secp256k1_detail::toString(y)};
        }
    }

end:
    util::free(a_ge);
    util::free(res_ge);

    util::free(a_gej);
    util::free(res_gej);

    return ret;
}

namespace secp256k1_detail {
    std::optional<component::Bignum> OpBignumCalc_Mod(operation::BignumCalc& op, const bool mod) {
        std::optional<component::Bignum> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        void* a = util::malloc(cryptofuzz_secp256k1_scalar_type_size());
        void* b = util::malloc(cryptofuzz_secp256k1_scalar_type_size());
        void* res = util::malloc(cryptofuzz_secp256k1_scalar_type_size());

        CF_CHECK_TRUE(secp256k1_detail::ToScalar(a, op.bn0));
        CF_CHECK_TRUE(secp256k1_detail::ToScalar(b, op.bn1));

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("IsZero(A)"):
                CF_NORET(cryptofuzz_secp256k1_scalar_set_int(
                            res,
                            cryptofuzz_secp256k1_scalar_is_zero(a)));
                break;
            case    CF_CALCOP("IsOne(A)"):
                CF_NORET(cryptofuzz_secp256k1_scalar_set_int(
                            res,
                            cryptofuzz_secp256k1_scalar_is_one(a)));
                break;
            case    CF_CALCOP("IsEven(A)"):
                CF_NORET(cryptofuzz_secp256k1_scalar_set_int(
                            res,
                            cryptofuzz_secp256k1_scalar_is_even(a)));
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                CF_NORET(cryptofuzz_secp256k1_scalar_set_int(
                            res,
                            cryptofuzz_secp256k1_scalar_eq(a, b)));
                break;
            case    CF_CALCOP("Add(A,B)"):
                {
                    const auto overflow = secp256k1_detail::CheckRet(
                            cryptofuzz_secp256k1_scalar_add(res, a, b)
                            );

                    /* Ignore overflow in mod mode */
                    if ( mod == false ) {
                        CF_CHECK_EQ(overflow, 0);
                    }
                }
                break;
            case    CF_CALCOP("Mul(A,B)"):
                CF_CHECK_TRUE(mod);
                CF_NORET(cryptofuzz_secp256k1_scalar_mul(res, a, b));
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                {
                    CF_CHECK_TRUE(mod);

                    bool var = false;
                    try { var = ds.Get<bool>(); } catch ( ... ) { }

                    if ( var == false ) {
                        CF_NORET(cryptofuzz_secp256k1_scalar_inverse(res, a));
                    } else {
                        CF_NORET(cryptofuzz_secp256k1_scalar_inverse_var(res, a));
                    }
                }
                break;
#if \
    !defined(SECP256K1_COMMIT_642cd062bdd2d28a8a84d4cb6dedbfe435ee5869) && \
    !defined(SECP256K1_COMMIT_c663397f46152e96c548ba392858c730e132dd7a) && \
    !defined(SECP256K1_COMMIT_cb32940df3e20ccdcbee7eaf5cda93c18a92fb3e) && \
    !defined(SECP255K1_COMMIT_9d560f992db26612ce2630b194aef5f44d63a530)
            case    CF_CALCOP("CondSet(A,B)"):
                memset(res, 0, cryptofuzz_secp256k1_scalar_type_size());
                CF_NORET(cryptofuzz_secp256k1_scalar_cmov(
                            res,
                            a,
                            !cryptofuzz_secp256k1_scalar_is_zero(b)));
                break;
#endif
            case    CF_CALCOP("Bit(A,B)"):
                {
                    std::optional<std::vector<uint8_t>> bin;
                    CF_CHECK_NE(bin = util::DecToBin(op.bn1.ToTrimmedString(), 1), std::nullopt);
                    const auto offset = bin->data()[0];
                    CF_CHECK_LT(offset, 32);

                    bool var = false;
                    try { var = ds.Get<bool>(); } catch ( ... ) { }

                    if ( var == false ) {
                        CF_NORET(cryptofuzz_secp256k1_scalar_set_int(
                                    res,
                                    cryptofuzz_secp256k1_scalar_get_bits(a, offset, 1)));
                    } else {
                        CF_NORET(cryptofuzz_secp256k1_scalar_set_int(
                                    res,
                                    cryptofuzz_secp256k1_scalar_get_bits_var(a, offset, 1)));
                    }
                }
                break;
            case    CF_CALCOP("Set(A)"):
                {
                    std::optional<std::vector<uint8_t>> bin;
                    CF_CHECK_NE(bin = util::DecToBin(op.bn0.ToTrimmedString(), 1), std::nullopt);
                    CF_NORET(cryptofuzz_secp256k1_scalar_set_int(res, bin->data()[0]));
                }
                break;
            case    CF_CALCOP("RShift(A,B)"):
                {
                    CF_CHECK_FALSE(mod);
                    std::optional<std::vector<uint8_t>> bin;
                    CF_CHECK_NE(bin = util::DecToBin(op.bn1.ToTrimmedString(), 1), std::nullopt);
                    CF_CHECK_GT(bin->data()[0], 0);
                    CF_CHECK_LT(bin->data()[0], 16);
                    /* ignore ret */ cryptofuzz_secp256k1_scalar_shr_int(a, bin->data()[0]);
                    memcpy(res, a, cryptofuzz_secp256k1_scalar_type_size());
                }
                break;
            default:
                goto end;
        }

        ret = secp256k1_detail::ToComponentBignum_scalar(res);

end:
        util::free(a);
        util::free(b);
        util::free(res);

        return ret;
    }

    std::optional<component::Bignum> OpBignumCalc_Prime(operation::BignumCalc& op, const bool mod) {
        std::optional<component::Bignum> ret = std::nullopt;
        if ( mod == false ) {
            /* XXX */
            return ret;
        }
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

        void* a = util::malloc(cryptofuzz_secp256k1_fe_size());
        void* b = util::malloc(cryptofuzz_secp256k1_fe_size());
        void* res = util::malloc(cryptofuzz_secp256k1_fe_size());

        CF_CHECK_TRUE(secp256k1_detail::ToFe(a, op.bn0));
        CF_CHECK_TRUE(secp256k1_detail::ToFe(b, op.bn1));

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                {
                    CF_NORET(cryptofuzz_secp256k1_fe_add(a, b));
                    memcpy(res, a, cryptofuzz_secp256k1_fe_size());
                }
                break;
            case    CF_CALCOP("Mul(A,B)"):
                {
                    CF_NORET(cryptofuzz_secp256k1_fe_mul(res, a, b));
                }
                break;
            case    CF_CALCOP("Sqr(A)"):
                {
                    CF_NORET(cryptofuzz_secp256k1_fe_sqr(res, a));
                }
                break;
            case    CF_CALCOP("InvMod(A,B)"):
                {
                    bool var = false;
                    try { var = ds.Get<bool>(); } catch ( ... ) { }

                    if ( var == false ) {
                        CF_NORET(cryptofuzz_secp256k1_fe_inv(res, a));
                    } else {
                        CF_NORET(cryptofuzz_secp256k1_fe_inv_var(res, a));
                    }
                }
                break;
            case    CF_CALCOP("Sqrt(A)"):
                {
                    if ( cryptofuzz_secp256k1_fe_sqrt(res, a) == 1 ) {
                        CF_NORET(cryptofuzz_secp256k1_fe_sqr(res, res));
                    } else {
                        CF_NORET(cryptofuzz_secp256k1_fe_clear(res));
                    }
                }
                break;
            case    CF_CALCOP("IsOdd(A)"):
                {
                    CF_NORET(cryptofuzz_secp256k1_fe_set_int(res,
                        cryptofuzz_secp256k1_fe_is_odd(a)
                    ));
                }
                break;
            case    CF_CALCOP("IsZero(A)"):
                {
                    CF_NORET(cryptofuzz_secp256k1_fe_set_int(res,
                        cryptofuzz_secp256k1_fe_is_zero(a)
                    ));
                }
                break;
            case    CF_CALCOP("IsEq(A,B)"):
                {
                    bool var = false;
                    try { var = ds.Get<bool>(); } catch ( ... ) { }

                    const int r =
                        var == false ?
                            cryptofuzz_secp256k1_fe_equal(a, b) :
                            cryptofuzz_secp256k1_fe_equal_var(a, b);

                    CF_NORET(cryptofuzz_secp256k1_fe_set_int(res, r));
                }
                break;
            case    CF_CALCOP("Cmp(A,B)"):
                {
                    const auto r = cryptofuzz_secp256k1_fe_cmp_var(a, b);

                    ret = component::Bignum(std::to_string(r));

                    goto end;
                }
                break;
            case    CF_CALCOP("CondSet(A,B)"):
                {
                    CF_NORET(cryptofuzz_secp256k1_fe_clear(res));

                    CF_NORET(cryptofuzz_secp256k1_fe_cmov(
                                res,
                                a,
                                !cryptofuzz_secp256k1_fe_is_zero(b)));
                }
                break;
            case    CF_CALCOP("Set(A)"):
                {
                    uint8_t which = 0;
                    try { which = ds.Get<uint8_t>() % 2; } catch ( ... ) { }

                    switch ( which ) {
                        case    0:
                            {
                                void* r = util::malloc(cryptofuzz_secp256k1_fe_storage_size());
                                CF_NORET(cryptofuzz_secp256k1_fe_to_storage(r, a));
                                CF_NORET(cryptofuzz_secp256k1_fe_from_storage(res, r));
                                util::free(r);
                            }
                            break;
                        case    1:
                            {
#ifdef SECP256K1_WIDEMUL_INT128
                                void* r = util::malloc(cryptofuzz_secp256k1_fe_signed62_size());
                                CF_NORET(cryptofuzz_secp256k1_fe_to_signed62(r, a));
                                CF_NORET(cryptofuzz_secp256k1_fe_from_signed62(res, r));
                                util::free(r);
#else
                                goto end;
#endif
                            }
                            break;
                        default:
                            CF_UNREACHABLE();
                            break;
                    }
                }
                break;
            default:
                goto end;
        }

        ret = secp256k1_detail::ToComponentBignum_fe(ds, res);

end:
        util::free(a);
        util::free(b);
        util::free(res);

        return ret;
    }
}

std::optional<component::Bignum> secp256k1::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return secp256k1_detail::OpBignumCalc_Mod(op, false);
    } else if ( op.modulo->ToTrimmedString() == "115792089237316195423570985008687907852837564279074904382605163141518161494337" ) {
        return secp256k1_detail::OpBignumCalc_Mod(op, true);
    } else if ( op.modulo->ToTrimmedString() == "115792089237316195423570985008687907853269984665640564039457584007908834671663" ) {
        return secp256k1_detail::OpBignumCalc_Prime(op, true);
    } else {
        return std::nullopt;
    }
}

#if 0
        case    CF_CALCOP("Sqrt(A)"):
            {
                secp256k1_fe_sqrt(&data->fe[0], &t);
            }
            break;
#endif

bool secp256k1::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
