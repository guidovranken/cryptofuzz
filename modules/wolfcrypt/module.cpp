#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include <iostream>

#if defined(CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED)
 #if UINTPTR_MAX != 0xFFFFFFFF
  #error "CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED only supported on 32 bit"
 #endif
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED)
#include <sys/mman.h>
#endif

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/md2.h>
#include <wolfssl/wolfcrypt/md4.h>
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/ripemd.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/blake2.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/rabbit.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/hc128.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/idea.h>

#include <wolfssl/wolfcrypt/hmac.h>

#include <wolfssl/wolfcrypt/cmac.h>

#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/curve448.h>
#include <wolfssl/wolfcrypt/ed448.h>
#include <wolfssl/wolfcrypt/ed25519.h>

#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
}

#include "bn_ops.h"
#include "ecdsa_generic.h"
#include "ecdsa_448.h"
#include "ecdsa_25519.h"

namespace cryptofuzz {
namespace module {

namespace wolfCrypt_detail {
    WC_RNG rng;
#if defined(WOLF_CRYPTO_CB)
    WC_RNG rng_deterministic;
#endif /* WOLF_CRYPTO_CB */


#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES) || defined(CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED)
    Datasource* ds;
#endif

#if defined(WOLF_CRYPTO_CB)
    int CryptoCB(int devId, wc_CryptoInfo* info, void* ctx) {
        (void)devId;
        (void)ctx;

        if (info->algo_type == WC_ALGO_TYPE_RNG) {
            try {
                if ( info->rng.sz ) {
                    const auto data = ds->GetData(0, info->rng.sz, info->rng.sz);
                    memcpy(info->rng.out, data.data(), info->rng.sz);
                }
            } catch ( ... ) {
                return -1;
            }

            return 0;
        } else if (info->algo_type == WC_ALGO_TYPE_SEED) {
            /* Taken from wolfcrypt/test/test.c */

            static byte seed[sizeof(word32)] = { 0x00, 0x00, 0x00, 0x01 };
            word32* seedWord32 = (word32*)seed;
            word32 len;

            /* wc_GenerateSeed is a local symbol so we need to fake the entropy. */
            while (info->seed.sz > 0) {
                len = (word32)sizeof(seed);
                if (info->seed.sz < len)
                    len = info->seed.sz;
                XMEMCPY(info->seed.seed, seed, sizeof(seed));
                info->seed.seed += len;
                info->seed.sz -= len;
                (*seedWord32)++;
            }
            return 0;
        }
        return NOT_COMPILED_IN;
    }
#endif /* WOLF_CRYPTO_CB */

#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
    bool disableAllocationFailures;
    bool haveAllocFailure;
#endif

    WC_RNG* GetRNG(void) {
#if defined(WOLF_CRYPTO_CB)
        if ( ds == nullptr ) {
            return &rng;
        }

        bool which = false; try { which = ds->Get<bool>(); } catch ( ... ) { }

        return which ? &rng_deterministic : &rng;
#else
        return &rng;
#endif
    }

    std::vector<std::pair<void*, size_t>> fixed_allocs;

    void SetGlobalDs(Datasource* ds) {
#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES) || defined(CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED)
#if defined(CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED)
        fixed_allocs.clear();
#endif
        wolfCrypt_detail::ds = ds;
#else
        (void)ds;
#endif
    }

    void UnsetGlobalDs(void) {
#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES) || defined(CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED)
        wolfCrypt_detail::ds = nullptr;
#endif
    }

    inline bool AllocationFailure(void) {
#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
        if ( disableAllocationFailures == true ) {
            return false;
        }

        bool fail = false;
        if ( ds == nullptr ) {
            if ( fail ) {
#if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
                std::cout << "Have allocation failure" << std::endl;
#endif
                haveAllocFailure = true;
            }
            return fail;
        }
        try {
            fail = ds->Get<bool>();
        } catch ( ... ) { }

        if ( fail ) {
#if defined(CRYPTOFUZZ_WOLFCRYPT_DEBUG)
            std::cout << "Have allocation failure" << std::endl;
#endif
            haveAllocFailure = true;
        }
        return fail;
#else
        return false;
#endif
    }

#if defined(CRYPTOFUZZ_WOLFCRYPT_MMAP_FIXED)
    bool isFixedAlloc(const void* ptr) {
        for (const auto& p : fixed_allocs) {
            if ( p.first == ptr ) {
                return true;
            }
        }
        return false;
    }

    void* fixed_alloc(const size_t n) {
        constexpr uint32_t top = 0xFFFFE000;
        const uint32_t preferred = (top - n) & 0xFFFFF000;

        for (const auto& p : fixed_allocs) {
            /* If an existing pointer overlaps with the preferred pointer, revert to normal mallo */
            if ( (void*)preferred >= p.first && (void*)preferred <= ((uint8_t*)p.first + p.second)) {
                return util::malloc(n);
            }
        }

        void* p = mmap(
                (void*)preferred,
                n,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS,
                -1,
                0);

        if ( p == (void*)0xFFFFFFFF ) {
            /* mmap failed, revert to normal malloc */
            return util::malloc(n);
        }

        fixed_allocs.push_back({p, n});

        return p;
    }

    void* malloc(const size_t n) {
        bool doFixedMmap = false;
        if ( ds == nullptr ) {
            goto end;
        }
        try {
            doFixedMmap = ds->Get<bool>();
        } catch ( ... ) { }
end:
        return doFixedMmap ? fixed_alloc(n) : util::malloc(n);
    }

    void* realloc(void* ptr, const size_t n) {
        if ( isFixedAlloc(ptr) ) {
            /* realloc currently not supported for mmap'ed regions */
            return nullptr;
        } else {
            return util::realloc(ptr, n);
        }
    }

    void free(void* ptr) {
        /* Find pointer in list */
        for (size_t i = 0; i < fixed_allocs.size(); i++) {
            if ( fixed_allocs[i].first == ptr ) {
                if ( munmap(ptr, fixed_allocs[i].second) != 0 ) {
                    abort();
                }

                /* Erase pointer from list */
                fixed_allocs.erase(fixed_allocs.begin() + i);

                return;
            }
        }

        util::free(ptr);
    }
#else
    void* malloc(const size_t n) {
        return util::malloc(n);
    }
    void* realloc(void* ptr, const size_t n) {
        return util::realloc(ptr, n);
    }
    void free(void* ptr) {
        util::free(ptr);
    }
#endif
}

static void* wolfCrypt_custom_malloc(size_t n) {
    return wolfCrypt_detail::AllocationFailure() ?
        nullptr :
        wolfCrypt_detail::malloc(n);
}

static void* wolfCrypt_custom_realloc(void* ptr, size_t n) {
    return wolfCrypt_detail::AllocationFailure() ?
        nullptr :
        wolfCrypt_detail::realloc(ptr, n);
}

static void wolfCrypt_custom_free(void* ptr) {
    wolfCrypt_detail::free(ptr);
}

wolfCrypt::wolfCrypt(void) :
    Module("wolfCrypt") {

#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
    wolfCrypt_detail::disableAllocationFailures = false;
#endif

    CF_ASSERT(wc_InitRng(&wolfCrypt_detail::rng) == 0, "Cannot initialize wolfCrypt RNG");

#if defined(WOLF_CRYPTO_CB)
    CF_NORET(wc_CryptoCb_Init());

    CF_ASSERT(wc_CryptoCb_RegisterDevice(0xAABBCC, wolfCrypt_detail::CryptoCB, nullptr) == 0, "Cannot initialize CryptoCB");
    CF_ASSERT(wc_InitRng_ex(&wolfCrypt_detail::rng_deterministic, nullptr, 0xAABBCC) == 0, "Cannot initialize deterministic wolfCrypt RNG");
#endif /* WOLF_CRYPTO_CB */

    wolfCrypt_detail::SetGlobalDs(nullptr);
    CF_ASSERT(wolfSSL_SetAllocators(wolfCrypt_custom_malloc, wolfCrypt_custom_free, wolfCrypt_custom_realloc) == 0, "Cannot set allocator functions");
}

namespace wolfCrypt_detail {
    template <class OperationType, class ReturnType, class CTXType>
    class Operation {
        protected:
            CTXType ctx;
        public:
            Operation(void) { }
            ~Operation() { }

            virtual bool runInit(OperationType& op) = 0;
            virtual bool runUpdate(util::Multipart& parts) = 0;
            virtual std::optional<ReturnType> runFinalize(void) = 0;
            virtual void runFree(void) = 0;
            virtual std::optional<ReturnType> runOneShot(const Buffer& in, Datasource& ds) = 0;

            std::optional<ReturnType> Run(OperationType& op, Datasource& ds) {
                std::optional<ReturnType> ret = std::nullopt;
                util::Multipart parts;

                bool doOneShot = false;
                try {
                    doOneShot = ds.Get<bool>();
                } catch ( ... ) { }

                if ( doOneShot == true ) {
                    ret = runOneShot(op.cleartext, ds);
                } else {
                    if ( runInit(op) == false ) {
                        return std::nullopt;
                    }

                    parts = util::ToParts(ds, op.cleartext);

                    CF_CHECK_EQ(runUpdate(parts), true);

                    ret = runFinalize();
                }

end:
                if ( doOneShot == false ) {
                    runFree();
                }
                return ret;
            }
    };

    template <class CTXType>
    class Init {
        public:
            virtual bool Initialize(CTXType* ctx) = 0;
            Init(void) { }
            virtual ~Init() { }
    };

    template <class CTXType>
    class Init_Void : public Init<CTXType> {
        public:
            using FnType = void (*)(CTXType*);
        private:
            FnType init;
        public:
            Init_Void(FnType init) :
                Init<CTXType>(),
                init(init)
            { }

            ~Init_Void() { }

            bool Initialize(CTXType* ctx) override {
                CF_NORET(init(ctx));
                return true;
            }
    };

    template <class CTXType>
    class Init_Int : public Init<CTXType> {
        public:
            using FnType = int (*)(CTXType*);
        private:
            FnType init;
        public:
            Init_Int(FnType init) :
                Init<CTXType>(),
                init(init)
            { }

            ~Init_Int() { }

            bool Initialize(CTXType* ctx) override {
                return init(ctx) == 0;
            }
    };

    template <class CTXType>
    class Init_IntParams : public Init<CTXType> {
        public:
            using FnType = int (*)(CTXType*, void*, int);
        private:
            FnType init;
        public:
            Init_IntParams(FnType init) :
                Init<CTXType>(),
                init(init)
            { }

            ~Init_IntParams() { }

            bool Initialize(CTXType* ctx) override {
                return init(ctx, nullptr, INVALID_DEVID) == 0;
            }
    };

    template <class CTXType, unsigned int Param>
    class Init_IntFixedParam : public Init<CTXType> {
        public:
            using FnType = int (*)(CTXType*, unsigned int);
        private:
            FnType init;
        public:
            Init_IntFixedParam(FnType init) :
                Init<CTXType>(),
                init(init)
            { }

            ~Init_IntFixedParam() { }

            bool Initialize(CTXType* ctx) override {
                return init(ctx, Param) == 0;
            }
    };

    template <class CTXType>
    class DigestUpdate {
        public:
            virtual bool Update(CTXType* ctx, const uint8_t* data, unsigned int size) = 0;
            DigestUpdate(void) { }
            virtual ~DigestUpdate() { }
    };

    template <class CTXType>
    class DigestUpdate_Void : public DigestUpdate<CTXType> {
        public:
            using FnType = void (*)(CTXType*, const uint8_t*, unsigned int);
        private:
            FnType update;
        public:
            DigestUpdate_Void(FnType update) :
                DigestUpdate<CTXType>(),
                update(update)
            { }

            ~DigestUpdate_Void() { }

            bool Update(CTXType* ctx, const uint8_t* data, unsigned int size) override {
                CF_NORET(update(ctx, data, size));
                return true;
            }
    };

    template <class CTXType>
    class DigestUpdate_Int : public DigestUpdate<CTXType> {
        public:
            using FnType = int (*)(CTXType*, const uint8_t*, unsigned int);
        private:
            FnType update;
        public:
            DigestUpdate_Int(FnType update) :
                DigestUpdate<CTXType>(),
                update(update)
            { }

            ~DigestUpdate_Int() { }

            bool Update(CTXType* ctx, const uint8_t* data, unsigned int size) override {
                return update(ctx, data, size) == 0;
            }
    };

    template <class CTXType>
    class DigestFinalize {
        public:
            virtual bool Finalize(CTXType* ctx, uint8_t* data) = 0;
            DigestFinalize(void) { }
            virtual ~DigestFinalize() { }
    };

    template <class CTXType>
    class DigestFinalize_Void : public DigestFinalize<CTXType> {
        public:
            using FnType = void (*)(CTXType*, uint8_t*);
        private:
            FnType finalize;
        public:
            DigestFinalize_Void(FnType finalize) :
                DigestFinalize<CTXType>(),
                finalize(finalize)
            { }

            ~DigestFinalize_Void() { }

            bool Finalize(CTXType* ctx, uint8_t* data) override {
                CF_NORET(finalize(ctx, data));
                return true;
            }
    };

    template <class CTXType>
    class DigestFinalize_Int : public DigestFinalize<CTXType> {
        public:
            using FnType = int (*)(CTXType*, uint8_t*);
        private:
            FnType finalize;
        public:
            DigestFinalize_Int(FnType finalize) :
                DigestFinalize<CTXType>(),
                finalize(finalize)
            { }

            ~DigestFinalize_Int() { }

            bool Finalize(CTXType* ctx, uint8_t* data) override {
                return finalize(ctx, data) == 0;
            }
    };

    template <class CTXType, unsigned int Param>
    class DigestFinalize_IntFixedParam : public DigestFinalize<CTXType> {
        public:
            using FnType = int (*)(CTXType*, uint8_t*, unsigned int);
        private:
            FnType finalize;
        public:
            DigestFinalize_IntFixedParam(FnType finalize) :
                DigestFinalize<CTXType>(),
                finalize(finalize)
            { }

            ~DigestFinalize_IntFixedParam() { }

            bool Finalize(CTXType* ctx, uint8_t* data) override {
                return finalize(ctx, data, Param) == 0;
            }
    };

    template <class CTXType, size_t DigestSize, class InitType, class UpdateType, class FinalizeType>
    class Digest : public Operation<operation::Digest, component::Digest, CTXType> {
        private:
            InitType init;
            UpdateType update;
            FinalizeType finalize;
            void (*freeCTX)(CTXType*);
            int (*copy)(CTXType*, CTXType*);
            int (*oneShot)(const byte*, word32, byte*);
            CTXType* getCtx(void) {
                bool doCopy = false;
                try {
                    doCopy = ds->Get<bool>();
                } catch ( ... ) { }
                if ( doCopy ) {
                    if ( copy != nullptr ) {
                        CTXType dest;
                        if ( copy(&this->ctx, &dest) == 0 ) {
                            memcpy(&this->ctx, &dest, sizeof(CTXType));
                        }
                    }
                }
                return &this->ctx;
            }
        public:
            Digest(
                typename InitType::FnType initFn,
                typename UpdateType::FnType updateFn,
                typename FinalizeType::FnType finalizeFn,
                void (*freeCTX)(CTXType*) = nullptr,
                int (*copy)(CTXType*, CTXType*) = nullptr,
                int (*oneShot)(const byte*, word32, byte*) = nullptr
            ) :
                Operation<operation::Digest, component::Digest, CTXType>(),
                init(initFn),
                update(updateFn),
                finalize(finalizeFn),
                freeCTX(freeCTX),
                copy(copy),
                oneShot(oneShot)
            { }

            bool runInit(operation::Digest& op) override {
                (void)op;
                return init.Initialize(&this->ctx);
            }

            bool runUpdate(util::Multipart& parts) override {
                for (const auto& part : parts) {
                    if ( update.Update(getCtx(), part.first, part.second) == false ) {
                        return false;
                    }
                }

                return true;
            }

            std::optional<component::Digest> runFinalize(void) override {
                std::vector<uint8_t> ret(DigestSize);

                if ( finalize.Finalize(getCtx(), ret.data()) == false ) {
                    return std::nullopt;
                }

                return component::Digest(ret.data(), ret.size());
            }

            void runFree(void) override {
                if ( freeCTX != nullptr ) {
                    freeCTX(&this->ctx);
                }
            }

            std::optional<component::Digest> runOneShot(const Buffer& in, Datasource& ds) override {
                std::optional<component::Digest> ret = std::nullopt;
                std::vector<uint8_t> out(DigestSize);

                CF_CHECK_NE(oneShot, nullptr);

                CF_CHECK_EQ(oneShot(in.GetPtr(&ds), in.GetSize() ,out.data()), 0);

                ret = component::Digest(out.data(), out.size());
end:
                return ret;
            }
    };


    Digest<Md2, MD2_DIGEST_SIZE, Init_Void<Md2>, DigestUpdate_Void<Md2>, DigestFinalize_Void<Md2>>
        md2(wc_InitMd2, wc_Md2Update, wc_Md2Final, nullptr, nullptr, wc_Md2Hash);

    Digest<Md4, MD4_DIGEST_SIZE, Init_Void<Md4>, DigestUpdate_Void<Md4>, DigestFinalize_Void<Md4>>
        md4(wc_InitMd4, wc_Md4Update, wc_Md4Final);

    Digest<Md5, MD5_DIGEST_SIZE, Init_IntParams<Md5>, DigestUpdate_Int<Md5>, DigestFinalize_Int<Md5>>
        md5(wc_InitMd5_ex, wc_Md5Update, wc_Md5Final, wc_Md5Free, wc_Md5Copy, wc_Md5Hash);

    Digest<RipeMd, RIPEMD_DIGEST_SIZE, Init_Int<RipeMd>, DigestUpdate_Int<RipeMd>, DigestFinalize_Int<RipeMd>>
        ripemd160(wc_InitRipeMd, wc_RipeMdUpdate, wc_RipeMdFinal);

    Digest<Sha, WC_SHA_DIGEST_SIZE, Init_Int<Sha>, DigestUpdate_Int<Sha>, DigestFinalize_Int<Sha>>
        sha1(wc_InitSha, wc_ShaUpdate, wc_ShaFinal, wc_ShaFree, wc_ShaCopy, wc_ShaHash);

    Digest<Sha224, WC_SHA224_DIGEST_SIZE, Init_Int<Sha224>, DigestUpdate_Int<Sha224>, DigestFinalize_Int<Sha224>>
        sha224(wc_InitSha224, wc_Sha224Update, wc_Sha224Final, wc_Sha224Free, wc_Sha224Copy, wc_Sha224Hash);

    Digest<Sha256, WC_SHA256_DIGEST_SIZE, Init_Int<Sha256>, DigestUpdate_Int<Sha256>, DigestFinalize_Int<Sha256>>
        sha256(wc_InitSha256, wc_Sha256Update, wc_Sha256Final, wc_Sha256Free, wc_Sha256Copy, wc_Sha256Hash);

    Digest<Sha384, WC_SHA384_DIGEST_SIZE, Init_Int<Sha384>, DigestUpdate_Int<Sha384>, DigestFinalize_Int<Sha384>>
        sha384(wc_InitSha384, wc_Sha384Update, wc_Sha384Final, wc_Sha384Free, wc_Sha384Copy, wc_Sha384Hash);

    Digest<Sha512, WC_SHA512_DIGEST_SIZE, Init_Int<Sha512>, DigestUpdate_Int<Sha512>, DigestFinalize_Int<Sha512>>
        sha512(wc_InitSha512, wc_Sha512Update, wc_Sha512Final, wc_Sha512Free, wc_Sha512Copy, wc_Sha512Hash);

    Digest<Sha3, WC_SHA3_224_DIGEST_SIZE, Init_IntParams<Sha3>, DigestUpdate_Int<Sha3>, DigestFinalize_Int<Sha3>>
        sha3_224(wc_InitSha3_224, wc_Sha3_224_Update, wc_Sha3_224_Final, wc_Sha3_224_Free, wc_Sha3_224_Copy, wc_Sha3_224Hash);

    Digest<Sha3, WC_SHA3_256_DIGEST_SIZE, Init_IntParams<Sha3>, DigestUpdate_Int<Sha3>, DigestFinalize_Int<Sha3>>
        sha3_256(wc_InitSha3_256, wc_Sha3_256_Update, wc_Sha3_256_Final, wc_Sha3_256_Free, wc_Sha3_256_Copy, wc_Sha3_256Hash);

    Digest<Sha3, WC_SHA3_384_DIGEST_SIZE, Init_IntParams<Sha3>, DigestUpdate_Int<Sha3>, DigestFinalize_Int<Sha3>>
        sha3_384(wc_InitSha3_384, wc_Sha3_384_Update, wc_Sha3_384_Final, wc_Sha3_384_Free, wc_Sha3_384_Copy, wc_Sha3_384Hash);

    Digest<Sha3, WC_SHA3_512_DIGEST_SIZE, Init_IntParams<Sha3>, DigestUpdate_Int<Sha3>, DigestFinalize_Int<Sha3>>
        sha3_512(wc_InitSha3_512, wc_Sha3_512_Update, wc_Sha3_512_Final, wc_Sha3_512_Free, wc_Sha3_512_Copy, wc_Sha3_512Hash);

    Digest<Blake2b, 64, Init_IntFixedParam<Blake2b, 64>, DigestUpdate_Int<Blake2b>, DigestFinalize_IntFixedParam<Blake2b, 64>>
        blake2b512(wc_InitBlake2b, wc_Blake2bUpdate, wc_Blake2bFinal);

    Digest<Blake2s, 32, Init_IntFixedParam<Blake2s, 32>, DigestUpdate_Int<Blake2s>, DigestFinalize_IntFixedParam<Blake2s, 32>>
        blake2s256(wc_InitBlake2s, wc_Blake2sUpdate, wc_Blake2sFinal);

    Digest<wc_Shake, 32, Init_IntParams<wc_Shake>, DigestUpdate_Int<wc_Shake>, DigestFinalize_IntFixedParam<wc_Shake, 32>>
        shake512(wc_InitShake256, wc_Shake256_Update, wc_Shake256_Final, wc_Shake256_Free, wc_Shake256_Copy);

    std::optional<wc_HashType> toHashType(const component::DigestType& digestType) {
        using fuzzing::datasource::ID;

        static const std::map<uint64_t, wc_HashType> LUT = {
            { CF_DIGEST("MD2"), WC_HASH_TYPE_MD2 },
            { CF_DIGEST("MD4"), WC_HASH_TYPE_MD4 },
            { CF_DIGEST("MD5"), WC_HASH_TYPE_MD5 },
            { CF_DIGEST("SHA1"), WC_HASH_TYPE_SHA },
            { CF_DIGEST("SHA224"), WC_HASH_TYPE_SHA224 },
            { CF_DIGEST("SHA256"), WC_HASH_TYPE_SHA256 },
            { CF_DIGEST("SHA384"), WC_HASH_TYPE_SHA384 },
            { CF_DIGEST("SHA512"), WC_HASH_TYPE_SHA512 },
            { CF_DIGEST("BLAKE2B512"), WC_HASH_TYPE_BLAKE2B },
            { CF_DIGEST("BLAKE2S256"), WC_HASH_TYPE_BLAKE2S },
            { CF_DIGEST("SHA3-224"), WC_HASH_TYPE_SHA3_224 },
            { CF_DIGEST("SHA3-256"), WC_HASH_TYPE_SHA3_256 },
            { CF_DIGEST("SHA3-384"), WC_HASH_TYPE_SHA3_384 },
            { CF_DIGEST("SHA3-512"), WC_HASH_TYPE_SHA3_512 },
            { CF_DIGEST("MD5_SHA1"), WC_HASH_TYPE_MD5_SHA },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(digestType.Get());
    }

    std::optional<size_t> toHashSize(const component::DigestType& digestType) {
        using fuzzing::datasource::ID;

        static const std::map<uint64_t, int> LUT = {
            { CF_DIGEST("MD2"), MD2_DIGEST_SIZE },
            { CF_DIGEST("MD4"), MD4_DIGEST_SIZE },
            { CF_DIGEST("MD5"), MD5_DIGEST_SIZE },
            { CF_DIGEST("SHA1"), WC_SHA_DIGEST_SIZE },
            { CF_DIGEST("SHA224"), WC_SHA224_DIGEST_SIZE },
            { CF_DIGEST("SHA256"), WC_SHA256_DIGEST_SIZE },
            { CF_DIGEST("SHA384"), WC_SHA384_DIGEST_SIZE },
            { CF_DIGEST("SHA512"), WC_SHA512_DIGEST_SIZE },
            { CF_DIGEST("BLAKE2B512"), BLAKE2B_OUTBYTES },
            { CF_DIGEST("BLAKE2S256"), BLAKE2S_OUTBYTES },
            { CF_DIGEST("SHA3-224"), WC_SHA3_224_DIGEST_SIZE },
            { CF_DIGEST("SHA3-256"), WC_SHA3_256_DIGEST_SIZE },
            { CF_DIGEST("SHA3-384"), WC_SHA3_384_DIGEST_SIZE },
            { CF_DIGEST("SHA3-512"), WC_SHA3_512_DIGEST_SIZE },
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(digestType.Get());
    }

    std::optional<component::Digest> DigestOneShot(operation::Digest& op, Datasource& ds) {
        std::optional<component::Digest> ret = std::nullopt;

        std::optional<wc_HashType> hashType;
        size_t hashSize;
        uint8_t* out = nullptr;

        CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);

        hashSize = wc_HashGetDigestSize(*hashType);
        out = util::malloc(hashSize);

        CF_CHECK_EQ(wc_Hash(
                    *hashType,
                    op.cleartext.GetPtr(&ds),
                    op.cleartext.GetSize(),
                    out,
                    hashSize), 0);

        ret = component::Digest(out, hashSize);
end:
        util::free(out);

        return ret;
    }
} /* namespace wolfCrypt_detail */

std::optional<component::Digest> wolfCrypt::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    bool useOneShot = false;
    try {
        useOneShot = ds.Get<bool>();
    } catch ( ... ) { }

    if ( useOneShot == true ) {
        ret = wolfCrypt_detail::DigestOneShot(op, ds);
    } else {
        switch ( op.digestType.Get() ) {
            case CF_DIGEST("MD2"):
                ret = wolfCrypt_detail::md2.Run(op, ds);
                break;
            case CF_DIGEST("MD4"):
                ret = wolfCrypt_detail::md4.Run(op, ds);
                break;
            case CF_DIGEST("MD5"):
                ret = wolfCrypt_detail::md5.Run(op, ds);
                break;
            case CF_DIGEST("RIPEMD160"):
                ret = wolfCrypt_detail::ripemd160.Run(op, ds);
                break;
            case CF_DIGEST("SHA1"):
                ret = wolfCrypt_detail::sha1.Run(op, ds);
                break;
            case CF_DIGEST("SHA224"):
                ret = wolfCrypt_detail::sha224.Run(op, ds);
                break;
            case CF_DIGEST("SHA256"):
                ret = wolfCrypt_detail::sha256.Run(op, ds);
                break;
            case CF_DIGEST("SHA384"):
                ret = wolfCrypt_detail::sha384.Run(op, ds);
                break;
            case CF_DIGEST("SHA512"):
                ret = wolfCrypt_detail::sha512.Run(op, ds);
                break;
            case CF_DIGEST("SHA3-224"):
                ret = wolfCrypt_detail::sha3_224.Run(op, ds);
                break;
            case CF_DIGEST("SHA3-256"):
                ret = wolfCrypt_detail::sha3_256.Run(op, ds);
                break;
            case CF_DIGEST("SHA3-384"):
                ret = wolfCrypt_detail::sha3_384.Run(op, ds);
                break;
            case CF_DIGEST("SHA3-512"):
                ret = wolfCrypt_detail::sha3_512.Run(op, ds);
                break;
            case CF_DIGEST("BLAKE2B512"):
                ret = wolfCrypt_detail::blake2b512.Run(op, ds);
                break;
            case CF_DIGEST("BLAKE2S256"):
                ret = wolfCrypt_detail::blake2s256.Run(op, ds);
                break;
            case CF_DIGEST("SHAKE256"):
                ret = wolfCrypt_detail::shake512.Run(op, ds);
                break;
        }
    }

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

namespace wolfCrypt_detail {
    std::optional<component::MAC> Blake2_MAC(operation::HMAC& op) {
        std::optional<component::MAC> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        wolfCrypt_detail::SetGlobalDs(&ds);

        Blake2b blake2b;
        Blake2s blake2s;

        util::Multipart parts;
        uint8_t out[64];

        if ( op.digestType.Is(CF_DIGEST("BLAKE2B_MAC")) ) {
            CF_CHECK_EQ(wc_InitBlake2b_WithKey(&blake2b, 64, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
        } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S_MAC")) ) {
            CF_CHECK_EQ(wc_InitBlake2s_WithKey(&blake2s, 64, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
        } else {
            abort();
        }

        parts = util::ToParts(ds, op.cleartext);

        if ( op.digestType.Is(CF_DIGEST("BLAKE2B_MAC")) ) {
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_Blake2bUpdate(&blake2b, part.first, part.second), 0);
            }
        } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S_MAC")) ) {
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_Blake2sUpdate(&blake2s, part.first, part.second), 0);
            }
        }

        if ( op.digestType.Is(CF_DIGEST("BLAKE2B_MAC")) ) {
            CF_CHECK_EQ(wc_Blake2bFinal(&blake2b, out, 64), 0);
        } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S_MAC")) ) {
            CF_CHECK_EQ(wc_Blake2sFinal(&blake2s, out, 64), 0);
        }

        ret = component::MAC(out, 64);
end:
        wolfCrypt_detail::UnsetGlobalDs();
        return ret;
    }
} /* namespace wolfCrypt_detail */

std::optional<component::MAC> wolfCrypt::OpHMAC(operation::HMAC& op) {
    if (
        op.digestType.Is(CF_DIGEST("BLAKE2B_MAC")) ||
        op.digestType.Is(CF_DIGEST("BLAKE2S_MAC")) ) {
        return wolfCrypt_detail::Blake2_MAC(op);
    }

    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<int> hashType;
    std::optional<size_t> hashSize;

    Hmac ctx;
    uint8_t* out = nullptr;
    util::Multipart parts;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);
        CF_CHECK_NE(hashSize = wolfCrypt_detail::toHashSize(op.digestType), std::nullopt);
        out = util::malloc(*hashSize);
        CF_CHECK_EQ(wc_HmacInit(&ctx, nullptr, INVALID_DEVID), 0);
        CF_CHECK_EQ(wc_HmacSetKey(&ctx, *hashType, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(wc_HmacUpdate(&ctx, part.first, part.second), 0);
    }

    /* Finalize */
    {
        CF_CHECK_EQ(wc_HmacFinal(&ctx, out), 0);

        ret = component::MAC(out, *hashSize);
    }

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Ciphertext> wolfCrypt::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = nullptr;
    uint8_t* outTag = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
        case CF_CIPHER("AES_192_CBC"):
        case CF_CIPHER("AES_256_CBC"):
        {
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            const auto cleartext = util::Pkcs7Pad(op.cleartext.Get(), 16);
            out = util::malloc(cleartext.size());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);
            CF_CHECK_EQ(wc_AesCbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

            ret = component::Ciphertext(Buffer(out, cleartext.size()));
        }
        break;

        case CF_CIPHER("CAMELLIA_128_CBC"):
        case CF_CIPHER("CAMELLIA_192_CBC"):
        case CF_CIPHER("CAMELLIA_256_CBC"):
        {
            Camellia ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("CAMELLIA_128_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("CAMELLIA_192_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("CAMELLIA_256_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            const auto cleartext = util::Pkcs7Pad(op.cleartext.Get(), 16);
            out = util::malloc(cleartext.size());

            CF_CHECK_EQ(wc_CamelliaSetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds)), 0);
            CF_CHECK_EQ(wc_CamelliaCbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

            ret = component::Ciphertext(Buffer(out, cleartext.size()));
        }
        break;

        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
        {
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_GCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_GCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_GCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_NE(op.aad, std::nullopt);

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

#ifdef WOLFSSL_AESGCM_STREAM
            /* Workarounds for bug */
            CF_CHECK_NE(op.cleartext.GetSize(), 0);
            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);

            CF_CHECK_EQ(wc_AesGcmInit(&ctx,
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);

            /* Pass AAD */
            {
                const auto parts = util::ToParts(ds, *op.aad);
                for (const auto& part : parts) {
                    CF_CHECK_EQ(wc_AesGcmEncryptUpdate(&ctx,
                                nullptr,
                                nullptr, 0,
                                part.first, part.second), 0);
                }
            }

            /* Pass cleartext */
            {
                const auto parts = util::ToParts(ds, op.cleartext);
                size_t pos = 0;
                for (const auto& part : parts) {
                    CF_CHECK_EQ(wc_AesGcmEncryptUpdate(&ctx,
                                out + pos,
                                part.first, part.second,
                                nullptr, 0), 0);
                    pos += part.second;
                }
            }

            CF_CHECK_EQ(wc_AesGcmEncryptFinal(&ctx, outTag, *op.tagSize), 0);
#else
            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesGcmSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_AesGcmEncrypt(
                        &ctx,
                        out,
                        op.cleartext.GetPtr(&ds),
                        op.cleartext.GetSize(),
                        op.cipher.iv.GetPtr(&ds),
                        op.cipher.iv.GetSize(),
                        outTag,
                        *op.tagSize,
                        op.aad->GetPtr(&ds),
                        op.aad->GetSize()), 0);
#endif

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;

        case CF_CIPHER("AES_128_CCM"):
        case CF_CIPHER("AES_192_CCM"):
        case CF_CIPHER("AES_256_CCM"):
        {
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_NE(op.aad, std::nullopt);

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesCcmSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_AesCcmEncrypt(
                        &ctx,
                        out,
                        op.cleartext.GetPtr(&ds),
                        op.cleartext.GetSize(),
                        op.cipher.iv.GetPtr(&ds),
                        op.cipher.iv.GetSize(),
                        outTag,
                        *op.tagSize,
                        op.aad->GetPtr(&ds),
                        op.aad->GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
        }
        break;

        case CF_CIPHER("CHACHA20_POLY1305"):
        {
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_GTE(*op.tagSize, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
            CF_CHECK_EQ(op.cipher.key.GetSize(), CHACHA20_POLY1305_AEAD_KEYSIZE);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA20_POLY1305_AEAD_IV_SIZE);
            CF_CHECK_NE(op.aad, std::nullopt);

            out = util::malloc(op.cleartext.GetSize());
            outTag = util::malloc(*op.tagSize);

            bool oneShot = true;
            try {
                oneShot = ds.Get<bool>();
            } catch ( ... ) { }

            if ( oneShot == true ) {
                CF_CHECK_EQ(wc_ChaCha20Poly1305_Encrypt(
                            op.cipher.key.GetPtr(&ds),
                            op.cipher.iv.GetPtr(&ds),
                            op.aad->GetPtr(&ds),
                            op.aad->GetSize(),
                            op.cleartext.GetPtr(&ds),
                            op.cleartext.GetSize(),
                            out,
                            outTag), 0);
            } else {
                ChaChaPoly_Aead aead;

                CF_CHECK_EQ(wc_ChaCha20Poly1305_Init(&aead, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), 1), 0);

                {
                    const auto partsAAD = util::ToParts(ds, *op.aad);
                    for (const auto& part : partsAAD) {
                        CF_CHECK_EQ(wc_ChaCha20Poly1305_UpdateAad(&aead, part.first, part.second), 0);
                    }
                }

                {
                    const auto partsData = util::ToParts(ds, op.cleartext);
                    size_t pos = 0;
                    for (const auto& part : partsData) {
                        CF_CHECK_EQ(wc_ChaCha20Poly1305_UpdateData(&aead, part.first, out + pos, part.second), 0);
                        pos += part.second;
                    }
                }

                CF_CHECK_EQ(wc_ChaCha20Poly1305_Final(&aead, outTag), 0);
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE));
        }
        break;

#if defined(HAVE_XCHACHA)
        case CF_CIPHER("XCHACHA20_POLY1305"):
        {
            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_GTE(*op.tagSize, CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
            CF_CHECK_NE(op.aad, std::nullopt);

            out = util::malloc(op.ciphertextSize);

            CF_CHECK_EQ(wc_XChaCha20Poly1305_Encrypt(
                        out, op.ciphertextSize,
                        op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                        op.aad->GetPtr(&ds), op.aad->GetSize(),
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize(),
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            ret = component::Ciphertext(
                    Buffer(out, op.cleartext.GetSize()),
                    Buffer(out + op.cleartext.GetSize(), CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE));
        }
        break;
#endif

        case CF_CIPHER("AES_128_CTR"):
        case CF_CIPHER("AES_192_CTR"):
        case CF_CIPHER("AES_256_CTR"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CTR"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CTR"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CTR"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCtrEncrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_ECB"):
        case CF_CIPHER("AES_192_ECB"):
        case CF_CIPHER("AES_256_ECB"):
        {
#if defined(HAVE_AES_ECB)
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_ECB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_ECB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_ECB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            /* Note: wc_AesEcbEncrypt does not support streaming */
            CF_CHECK_EQ(wc_AesEcbEncrypt(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
#endif
        }
        break;

        case CF_CIPHER("HC128"):
        {
            HC128 ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_Hc128_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds)), 0);

            CF_CHECK_EQ(wc_Hc128_Process(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_XTS"):
        case CF_CIPHER("AES_192_XTS"):
        case CF_CIPHER("AES_256_XTS"):
        {
            XtsAes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_XTS"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_XTS"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_XTS"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_AesXtsSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), AES_ENCRYPTION, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesXtsEncrypt(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize(), op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB"):
        case CF_CIPHER("AES_192_CFB"):
        case CF_CIPHER("AES_256_CFB"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCfbEncrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB1"):
        case CF_CIPHER("AES_192_CFB1"):
        case CF_CIPHER("AES_256_CFB1"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CFB1"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CFB1"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CFB1"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCfb1Encrypt(&ctx, out + outIdx, part.first, part.second * 8), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB8"):
        case CF_CIPHER("AES_192_CFB8"):
        case CF_CIPHER("AES_256_CFB8"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CFB8"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CFB8"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CFB8"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCfb8Encrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_OFB"):
        case CF_CIPHER("AES_192_OFB"):
        case CF_CIPHER("AES_256_OFB"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_OFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_OFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_OFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cleartext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesOfbEncrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("RC4"):
        {
            Arc4 ctx;

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_Arc4Init(&ctx, NULL, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_Arc4SetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_Arc4Process(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("RABBIT"):
        {
            Rabbit ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_RabbitSetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.iv.GetPtr(&ds)), 0);

            CF_CHECK_EQ(wc_RabbitProcess(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("CHACHA20"):
        {
            ChaCha ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA_IV_BYTES);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_Chacha_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_Chacha_SetIV(&ctx, op.cipher.iv.GetPtr(&ds), 0), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_Chacha_Process(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("DES_CBC"):
        {
            Des ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 8);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);

            const auto cleartext = util::Pkcs7Pad(op.cleartext.Get(), 8);
            out = util::malloc(cleartext.size());

            CF_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_ENCRYPTION), 0);
            CF_CHECK_EQ(wc_Des_CbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

            ret = component::Ciphertext(Buffer(out, cleartext.size()));
        }
        break;

        case CF_CIPHER("DES3_CBC"):
        {
            Des3 ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 24);

            const auto cleartext = util::Pkcs7Pad(op.cleartext.Get(), 8);
            out = util::malloc(cleartext.size());

            CF_CHECK_EQ(wc_Des3_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_ENCRYPTION), 0);
            CF_CHECK_EQ(wc_Des3_CbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

            ret = component::Ciphertext(Buffer(out, cleartext.size()));
        }
        break;

        case CF_CIPHER("IDEA_CBC"):
        {
            Idea ctx;

            CF_CHECK_EQ(op.cipher.iv.GetSize(), IDEA_BLOCK_SIZE);

            const auto cleartext = util::Pkcs7Pad(op.cleartext.Get(), IDEA_BLOCK_SIZE);
            out = util::malloc(cleartext.size());

            CF_CHECK_EQ(wc_IdeaSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), IDEA_ENCRYPTION), 0);
            CF_CHECK_EQ(wc_IdeaCbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

            ret = component::Ciphertext(Buffer(out, cleartext.size()));
        }
        break;

        case CF_CIPHER("DES_ECB"):
        {
#if defined(WOLFSSL_DES_ECB)
            Des ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 8);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);
            CF_CHECK_EQ(op.cleartext.GetSize() % 8, 0);

            out = util::malloc(op.cleartext.GetSize());

            CF_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_ENCRYPTION), 0);
            CF_CHECK_EQ(wc_Des_EcbEncrypt(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
#endif
        }
        break;

        case CF_CIPHER("AES_128_WRAP"):
        case CF_CIPHER("AES_192_WRAP"):
        case CF_CIPHER("AES_256_WRAP"):
        {
            int outSize;
            CF_CHECK_EQ(op.cipher.iv.GetSize(), KEYWRAP_BLOCK_SIZE);

            out = util::malloc(op.ciphertextSize);

            CF_CHECK_GTE(outSize = wc_AesKeyWrap(
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                        out, op.ciphertextSize,
                        op.cipher.iv.GetPtr(&ds)), 0);

            ret = component::Ciphertext(Buffer(out, outSize));
        }
        break;

        case CF_CIPHER("GMAC_128"):
        case CF_CIPHER("GMAC_192"):
        case CF_CIPHER("GMAC_256"):
        {

            CF_CHECK_NE(op.tagSize, std::nullopt);
            CF_CHECK_NE(op.aad, std::nullopt);

            outTag = util::malloc(*op.tagSize);
            const auto partsAAD = util::ToParts(ds, *op.aad);

            Gmac ctx;
            CF_CHECK_EQ(wc_AesInit(&ctx.aes, NULL, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_GmacSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_GmacUpdate(&ctx,
                        op.cipher.iv.GetPtr(&ds),
                        op.cipher.iv.GetSize(),
                        op.aad->GetPtr(&ds),
                        op.aad->GetSize(),
                        outTag, *op.tagSize), 0);
            wc_AesFree(&ctx.aes);

            ret = component::Ciphertext(
                    Buffer(op.cleartext.GetPtr(&ds), op.cleartext.GetSize()),
                    Buffer(outTag, *op.tagSize));
        }
        break;
    }

end:
    util::free(out);
    util::free(outTag);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Cleartext> wolfCrypt::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* in = nullptr;
    uint8_t* out = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
        case CF_CIPHER("AES_192_CBC"):
        case CF_CIPHER("AES_256_CBC"):
        {
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_DECRYPTION), 0);
            CF_CHECK_EQ(wc_AesCbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), AES_BLOCK_SIZE );
            CF_CHECK_NE(unpaddedCleartext, std::nullopt);
            ret = component::Cleartext(Buffer(*unpaddedCleartext));
        }
        break;

        case CF_CIPHER("CAMELLIA_128_CBC"):
        case CF_CIPHER("CAMELLIA_192_CBC"):
        case CF_CIPHER("CAMELLIA_256_CBC"):
        {
            Camellia ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("CAMELLIA_128_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("CAMELLIA_192_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("CAMELLIA_256_CBC"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_CamelliaSetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds)), 0);
            CF_CHECK_EQ(wc_CamelliaCbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), CAMELLIA_BLOCK_SIZE );
            CF_CHECK_NE(unpaddedCleartext, std::nullopt);
            ret = component::Cleartext(Buffer(*unpaddedCleartext));
        }
        break;

        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
        {
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_GCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_GCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_GCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_NE(op.aad, std::nullopt);
            CF_CHECK_NE(op.tag, std::nullopt);

            out = util::malloc(op.ciphertext.GetSize());

#ifdef WOLFSSL_AESGCM_STREAM
            /* Workaround for bug */
            CF_CHECK_NE(op.cipher.iv.GetSize(), 0);

            CF_CHECK_EQ(wc_AesGcmInit(&ctx,
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);
            /* Pass AAD */
            {
                const auto parts = util::ToParts(ds, *op.aad);
                for (const auto& part : parts) {
                    CF_CHECK_EQ(wc_AesGcmDecryptUpdate(&ctx,
                                nullptr,
                                nullptr, 0,
                                part.first, part.second), 0);
                }
            }

            /* Pass ciphertext */
            {
                const auto parts = util::ToParts(ds, op.ciphertext);
                size_t pos = 0;
                for (const auto& part : parts) {
                    /* Workaround for bug */
                    CF_CHECK_NE(part.second, 0);

                    CF_CHECK_EQ(wc_AesGcmDecryptUpdate(&ctx,
                                out + pos,
                                part.first, part.second,
                                nullptr, 0), 0);
                    pos += part.second;
                }
            }

            CF_CHECK_EQ(wc_AesGcmDecryptFinal(&ctx, op.tag->GetPtr(&ds), op.tag->GetSize()), 0);
#else
            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesGcmSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_AesGcmDecrypt(
                        &ctx,
                        out,
                        op.ciphertext.GetPtr(&ds),
                        op.ciphertext.GetSize(),
                        op.cipher.iv.GetPtr(&ds),
                        op.cipher.iv.GetSize(),
                        op.tag->GetPtr(&ds),
                        op.tag->GetSize(),
                        op.aad->GetPtr(&ds),
                        op.aad->GetSize()), 0);
#endif

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CCM"):
        case CF_CIPHER("AES_192_CCM"):
        case CF_CIPHER("AES_256_CCM"):
        {
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CCM"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_NE(op.aad, std::nullopt);
            CF_CHECK_NE(op.tag, std::nullopt);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesCcmSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_AesCcmDecrypt(
                        &ctx,
                        out,
                        op.ciphertext.GetPtr(&ds),
                        op.ciphertext.GetSize(),
                        op.cipher.iv.GetPtr(&ds),
                        op.cipher.iv.GetSize(),
                        op.tag->GetPtr(&ds),
                        op.tag->GetSize(),
                        op.aad->GetPtr(&ds),
                        op.aad->GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("CHACHA20_POLY1305"):
        {
            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_EQ(op.tag->GetSize(), CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
            CF_CHECK_EQ(op.cipher.key.GetSize(), CHACHA20_POLY1305_AEAD_KEYSIZE);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA20_POLY1305_AEAD_IV_SIZE);
            CF_CHECK_NE(op.aad, std::nullopt);

            out = util::malloc(op.ciphertext.GetSize());

            bool oneShot = true;
            try {
                oneShot = ds.Get<bool>();
            } catch ( ... ) { }

            if ( oneShot == true ) {
                CF_CHECK_EQ(wc_ChaCha20Poly1305_Decrypt(
                            op.cipher.key.GetPtr(&ds),
                            op.cipher.iv.GetPtr(&ds),
                            op.aad->GetPtr(&ds),
                            op.aad->GetSize(),
                            op.ciphertext.GetPtr(&ds),
                            op.ciphertext.GetSize(),
                            op.tag->GetPtr(&ds),
                            out), 0);
            } else {
                ChaChaPoly_Aead aead;

                CF_CHECK_EQ(wc_ChaCha20Poly1305_Init(&aead, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), 0), 0);

                {
                    const auto partsAAD = util::ToParts(ds, *op.aad);
                    for (const auto& part : partsAAD) {
                        CF_CHECK_EQ(wc_ChaCha20Poly1305_UpdateAad(&aead, part.first, part.second), 0);
                    }
                }

                {
                    const auto partsData = util::ToParts(ds, op.ciphertext);
                    size_t pos = 0;
                    for (const auto& part : partsData) {
                        CF_CHECK_EQ(wc_ChaCha20Poly1305_UpdateData(&aead, part.first, out + pos, part.second), 0);
                        pos += part.second;
                    }

                }

                {
                    uint8_t outTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
                    CF_CHECK_EQ(wc_ChaCha20Poly1305_Final(&aead, outTag), 0);
                    CF_CHECK_EQ(wc_ChaCha20Poly1305_CheckTag(outTag, op.tag->GetPtr(&ds)), 0);
                }
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

#if defined(HAVE_XCHACHA)
        case CF_CIPHER("XCHACHA20_POLY1305"):
        {
            const size_t inSize = op.ciphertext.GetSize() + CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_EQ(op.tag->GetSize(), CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
            CF_CHECK_NE(op.aad, std::nullopt);

            /* Concatenate ciphertext + tag */
            in = util::malloc(inSize);
            if ( op.ciphertext.GetSize() ) {
                memcpy(in, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize());
            }
            memcpy(in + op.ciphertext.GetSize(), op.tag->GetPtr(&ds), op.tag->GetSize());

            out = util::malloc(op.cleartextSize);

            CF_CHECK_EQ(wc_XChaCha20Poly1305_Decrypt(
                        out, op.cleartextSize,
                        in, inSize,
                        op.aad->GetPtr(&ds), op.aad->GetSize(),
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize(),
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;
#endif

        case CF_CIPHER("AES_128_CTR"):
        case CF_CIPHER("AES_192_CTR"):
        case CF_CIPHER("AES_256_CTR"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CTR"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CTR"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CTR"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCtrEncrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_ECB"):
        case CF_CIPHER("AES_192_ECB"):
        case CF_CIPHER("AES_256_ECB"):
        {
#if defined(HAVE_AES_ECB)
            Aes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_ECB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_ECB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_ECB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_DECRYPTION), 0);

            /* Note: wc_AesEcbDecrypt does not support streaming */
            CF_CHECK_EQ(wc_AesEcbDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
#endif
        }
        break;

        case CF_CIPHER("HC128"):
        {
            HC128 ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_Hc128_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds)), 0);
            CF_CHECK_EQ(wc_Hc128_Process(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_XTS"):
        case CF_CIPHER("AES_192_XTS"):
        case CF_CIPHER("AES_256_XTS"):
        {
            XtsAes ctx;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_XTS"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_XTS"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_XTS"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesXtsSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), AES_DECRYPTION, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesXtsDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize(), op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB"):
        case CF_CIPHER("AES_192_CFB"):
        case CF_CIPHER("AES_256_CFB"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCfbDecrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB1"):
        case CF_CIPHER("AES_192_CFB1"):
        case CF_CIPHER("AES_256_CFB1"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CFB1"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CFB1"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CFB1"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCfb1Decrypt(&ctx, out + outIdx, part.first, part.second * 8), 0);
                outIdx += part.second;
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB8"):
        case CF_CIPHER("AES_192_CFB8"):
        case CF_CIPHER("AES_256_CFB8"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_CFB8"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_CFB8"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_CFB8"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesCfb8Decrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_OFB"):
        case CF_CIPHER("AES_192_OFB"):
        case CF_CIPHER("AES_256_OFB"):
        {
            Aes ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            switch ( op.cipher.cipherType.Get() ) {
                case CF_CIPHER("AES_128_OFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                    break;
                case CF_CIPHER("AES_192_OFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                    break;
                case CF_CIPHER("AES_256_OFB"):
                    CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                    break;
            }

            CF_CHECK_EQ(op.ciphertext.GetSize() % 16, 0);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 16);
            CF_CHECK_GT(op.cipher.key.GetSize(), 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_AesOfbDecrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("RC4"):
        {
            Arc4 ctx;

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_Arc4Init(&ctx, NULL, INVALID_DEVID), 0);
            CF_CHECK_EQ(wc_Arc4SetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_Arc4Process(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("RABBIT"):
        {
            Rabbit ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_RabbitSetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.iv.GetPtr(&ds)), 0);
            CF_CHECK_EQ(wc_RabbitProcess(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("CHACHA20"):
        {
            ChaCha ctx;
            util::Multipart parts;
            size_t outIdx = 0;

            CF_CHECK_EQ(op.cipher.iv.GetSize(), CHACHA_IV_BYTES);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_Chacha_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            CF_CHECK_EQ(wc_Chacha_SetIV(&ctx, op.cipher.iv.GetPtr(&ds), 0), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                CF_CHECK_EQ(wc_Chacha_Process(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("DES_CBC"):
        {
            Des ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 8);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_DECRYPTION), 0);
            CF_CHECK_EQ(wc_Des_CbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), DES_BLOCK_SIZE );
            CF_CHECK_NE(unpaddedCleartext, std::nullopt);
            ret = component::Cleartext(Buffer(*unpaddedCleartext));
        }
        break;

        case CF_CIPHER("DES3_CBC"):
        {
            Des3 ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 24);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_Des3_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_DECRYPTION), 0);
            CF_CHECK_EQ(wc_Des3_CbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), DES_BLOCK_SIZE );
            CF_CHECK_NE(unpaddedCleartext, std::nullopt);
            ret = component::Cleartext(Buffer(*unpaddedCleartext));
        }
        break;

        case CF_CIPHER("IDEA_CBC"):
        {
            Idea ctx;

            CF_CHECK_EQ(op.cipher.iv.GetSize(), IDEA_BLOCK_SIZE);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_IdeaSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), IDEA_DECRYPTION), 0);
            CF_CHECK_EQ(wc_IdeaCbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), IDEA_BLOCK_SIZE );
            CF_CHECK_NE(unpaddedCleartext, std::nullopt);
            ret = component::Cleartext(Buffer(*unpaddedCleartext));
        }
        break;

        case CF_CIPHER("DES_ECB"):
        {
#if defined(WOLFSSL_DES_ECB)
            Des ctx;

            CF_CHECK_EQ(op.cipher.key.GetSize(), 8);
            CF_CHECK_EQ(op.cipher.iv.GetSize(), 8);
            CF_CHECK_EQ(op.ciphertext.GetSize() % 8, 0);

            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_DECRYPTION), 0);
            CF_CHECK_EQ(wc_Des_EcbDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
#endif
        }
        break;

        case CF_CIPHER("AES_128_WRAP"):
        case CF_CIPHER("AES_192_WRAP"):
        case CF_CIPHER("AES_256_WRAP"):
        {
            int outSize;
            CF_CHECK_EQ(op.cipher.iv.GetSize(), KEYWRAP_BLOCK_SIZE);

            out = util::malloc(op.cleartextSize);

            CF_CHECK_GTE(outSize = wc_AesKeyUnWrap(
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize(),
                        out, op.cleartextSize,
                        op.cipher.iv.GetPtr(&ds)), 0);

            ret = component::Cleartext(Buffer(out, outSize));
        }
        break;

        case CF_CIPHER("GMAC_128"):
        case CF_CIPHER("GMAC_192"):
        case CF_CIPHER("GMAC_256"):
        {
            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_NE(op.aad, std::nullopt);

            CF_CHECK_EQ(wc_GmacVerify(
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds),
                        op.cipher.iv.GetSize(),
                        op.aad->GetPtr(&ds),
                        op.aad->GetSize(),
                        op.tag->GetPtr(&ds),
                        op.tag->GetSize()), 0);

            ret = component::Cleartext(Buffer(op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()));
        }
        break;
    }

end:
    util::free(in);
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::MAC> wolfCrypt::OpCMAC(operation::CMAC& op) {
    /* Other ciphers not supported for CMAC in wolfCrypt */
    if ( op.cipher.cipherType.Get() != CF_CIPHER("AES") ) {
        return std::nullopt;
    }

    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    Cmac ctx;
    uint8_t out[AES_BLOCK_SIZE];
    util::Multipart parts;
    uint32_t outSize = sizeof(out);

    bool useOneShot = true;

    try {
        useOneShot = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    if ( useOneShot == true ) {
        CF_CHECK_EQ(wc_AesCmacGenerate(
                    out,
                    &outSize,
                    op.cleartext.GetPtr(&ds),
                    op.cleartext.GetSize(),
                    op.cipher.key.GetPtr(&ds),
                    op.cipher.key.GetSize()), 0);
    } else { /* Multi-part CMAC */

        /* Initialize */
        {
            parts = util::ToParts(ds, op.cleartext);

            CF_CHECK_EQ(wc_InitCmac(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), WC_CMAC_AES, nullptr), 0);
        }

        /* Process */
        for (const auto& part : parts) {
            CF_CHECK_EQ(wc_CmacUpdate(&ctx, part.first, part.second), 0);
        }

        /* Finalize */
        {
            CF_CHECK_EQ(wc_CmacFinal(&ctx, out, &outSize), 0);
            ret = component::MAC(out, outSize);
        }
    }

    CF_ASSERT(wc_AesCmacVerify(
                    out,
                    outSize,
                    op.cleartext.GetPtr(&ds),
                    op.cleartext.GetSize(),
                    op.cipher.key.GetPtr(&ds),
                    op.cipher.key.GetSize()) == 0,
            "Cannot verify self-generated CMAC");
end:

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> wolfCrypt::OpKDF_PBKDF(operation::KDF_PBKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = util::malloc(op.keySize);

    const auto hashType = wolfCrypt_detail::toHashType(op.digestType);

    CF_CHECK_NE(hashType, std::nullopt);

    CF_CHECK_EQ(wc_PKCS12_PBKDF(out,
                op.password.GetPtr(&ds),
                op.password.GetSize(),
                op.salt.GetPtr(&ds),
                op.salt.GetSize(),
                op.iterations,
                op.keySize,
                *hashType,
                1), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> wolfCrypt::OpKDF_PBKDF1(operation::KDF_PBKDF1& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = util::malloc(op.keySize);

    const auto hashType = wolfCrypt_detail::toHashType(op.digestType);

    CF_CHECK_NE(hashType, std::nullopt);

    CF_CHECK_EQ(
            wc_PBKDF1(
                out,
                op.password.GetPtr(&ds),
                op.password.GetSize(),
                op.salt.GetPtr(&ds),
                op.salt.GetSize(),
                op.iterations,
                op.keySize,
                *hashType), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> wolfCrypt::OpKDF_PBKDF2(operation::KDF_PBKDF2& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = util::malloc(op.keySize);

    const auto hashType = wolfCrypt_detail::toHashType(op.digestType);

    CF_CHECK_NE(hashType, std::nullopt);

    CF_CHECK_EQ(
            wc_PBKDF2(
                out,
                op.password.GetPtr(&ds),
                op.password.GetSize(),
                op.salt.GetPtr(&ds),
                op.salt.GetSize(),
                op.iterations,
                op.keySize,
                *hashType), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> wolfCrypt::OpKDF_SCRYPT(operation::KDF_SCRYPT& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = util::malloc(op.keySize);

    const size_t N = op.N >> 1;

    CF_CHECK_EQ(N << 1, op.N);
    CF_CHECK_GT(op.p, 0);

    CF_CHECK_EQ(wc_scrypt(
            out,
            op.password.GetPtr(&ds),
            op.password.GetSize(),
            op.salt.GetPtr(&ds),
            op.salt.GetSize(),
            op.N >> 1,
            op.r,
            op.p,
            op.keySize), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> wolfCrypt::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = util::malloc(op.keySize);

    auto hashType = wolfCrypt_detail::toHashType(op.digestType);

    CF_CHECK_NE(hashType, std::nullopt);

    CF_CHECK_EQ(wc_HKDF(
                *hashType,
                op.password.GetPtr(&ds),
                op.password.GetSize(),
                op.salt.GetPtr(&ds),
                op.salt.GetSize(),
                op.info.GetPtr(&ds),
                op.info.GetSize(),
                out,
                op.keySize), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> wolfCrypt::OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("MD5_SHA1"));

    CF_CHECK_EQ(wc_PRF_TLSv1(out,
            op.keySize,
            op.secret.GetPtr(&ds),
            op.secret.GetSize(),
            nullptr,
            0,
            op.seed.GetPtr(&ds),
            op.seed.GetSize(),
            nullptr,
            INVALID_DEVID), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Key> wolfCrypt::OpKDF_X963(operation::KDF_X963& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = util::malloc(op.keySize);

    auto hashType = wolfCrypt_detail::toHashType(op.digestType);

    CF_CHECK_NE(hashType, std::nullopt);

    CF_CHECK_EQ(wc_X963_KDF(
            *hashType,
            op.secret.GetPtr(&ds),
            op.secret.GetSize(),
            op.info.GetPtr(&ds),
            op.info.GetSize(),
            out,
            op.keySize), 0);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

namespace wolfCrypt_detail {
    std::optional<int> toCurveID(const component::CurveType& curveType) {
        static const std::map<uint64_t, int> LUT = {
            /* Reference: wolfssl/wolfcrypt/ecc.h */

            /* NIST */
            { CF_ECC_CURVE("secp192r1"), ECC_SECP192R1 },
            { CF_ECC_CURVE("secp256r1"), ECC_SECP256R1 },

            /* SECP */
            { CF_ECC_CURVE("secp112r1"), ECC_SECP112R1 },
            { CF_ECC_CURVE("secp112r2"), ECC_SECP112R2 },
            { CF_ECC_CURVE("secp128r1"), ECC_SECP128R1 },
            { CF_ECC_CURVE("secp128r2"), ECC_SECP128R2 },
            { CF_ECC_CURVE("secp160r1"), ECC_SECP160R1 },
            { CF_ECC_CURVE("secp160r2"), ECC_SECP160R2 },
            { CF_ECC_CURVE("secp224r1"), ECC_SECP224R1 },
            { CF_ECC_CURVE("secp384r1"), ECC_SECP384R1 },
            { CF_ECC_CURVE("secp521r1"), ECC_SECP521R1 },

            /* Koblitz */
            { CF_ECC_CURVE("secp160k1"), ECC_SECP160K1 },
            { CF_ECC_CURVE("secp192k1"), ECC_SECP192K1 },
            { CF_ECC_CURVE("secp224k1"), ECC_SECP224K1 },
            { CF_ECC_CURVE("secp256k1"), ECC_SECP256K1 },

            /* Brainpool */
            { CF_ECC_CURVE("brainpool160r1"), ECC_BRAINPOOLP160R1 },
            { CF_ECC_CURVE("brainpool192r1"), ECC_BRAINPOOLP192R1 },
            { CF_ECC_CURVE("brainpool224r1"), ECC_BRAINPOOLP224R1 },
            { CF_ECC_CURVE("brainpool256r1"), ECC_BRAINPOOLP256R1 },
            { CF_ECC_CURVE("brainpool320r1"), ECC_BRAINPOOLP320R1 },
            { CF_ECC_CURVE("brainpool384r1"), ECC_BRAINPOOLP384R1 },
            { CF_ECC_CURVE("brainpool512r1"), ECC_BRAINPOOLP512R1 },

            /* ANSI X9.62 */
            { CF_ECC_CURVE("x962_p192v2"), ECC_PRIME192V2 },
            { CF_ECC_CURVE("x962_p192v3"), ECC_PRIME192V3 },
            { CF_ECC_CURVE("x962_p239v1"), ECC_PRIME239V1 },
            { CF_ECC_CURVE("x962_p239v2"), ECC_PRIME239V2 },
            { CF_ECC_CURVE("x962_p239v3"), ECC_PRIME239V3 },
        };

        if ( LUT.find(curveType.Get()) == LUT.end() ) {
            return std::nullopt;
        }

        return LUT.at(curveType.Get());
    }
}

std::optional<component::ECC_PublicKey> wolfCrypt::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    if ( op.curveType.Get() == CF_ECC_CURVE("x25519") ) {
        return wolfCrypt_detail::OpECC_PrivateToPublic_Curve25519(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("x448") ) {
        return wolfCrypt_detail::OpECC_PrivateToPublic_Curve448(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
        return wolfCrypt_detail::OpECC_PrivateToPublic_Ed25519(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed448") ) {
        return wolfCrypt_detail::OpECC_PrivateToPublic_Ed448(op);
    } else {
        return wolfCrypt_detail::OpECC_PrivateToPublic_Generic(op);
    }
}

std::optional<bool> wolfCrypt::OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    if ( op.curveType.Get() == CF_ECC_CURVE("x25519") ) {
        return wolfCrypt_detail::OpECC_ValidatePubkey_Curve25519(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("x448") ) {
        return wolfCrypt_detail::OpECC_ValidatePubkey_Curve448(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
        return wolfCrypt_detail::OpECC_ValidatePubkey_Ed25519(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed448") ) {
        return wolfCrypt_detail::OpECC_ValidatePubkey_Ed448(op);
    } else {
        return wolfCrypt_detail::OpECC_ValidatePubkey_Generic(op);
    }
}

std::optional<component::ECC_KeyPair> wolfCrypt::OpECC_GenerateKeyPair(operation::ECC_GenerateKeyPair& op) {
    std::optional<component::ECC_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<std::string> priv_str, pub_x_str, pub_y_str;
    ecc_key* key = nullptr;
    uint8_t* priv_bytes = nullptr, *pub_bytes = nullptr;
    word32 outSize = 0;

    if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
        ed25519_key key;

        CF_CHECK_EQ(wc_ed25519_make_key(wolfCrypt_detail::GetRNG(), ED25519_KEY_SIZE, &key), 0);

        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_ed25519_check_key(&key) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_ed25519_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_ed25519_export_private_only(&key, priv_bytes, &outSize), 0);
            CF_ASSERT(outSize = ED25519_KEY_SIZE,
                    "Private key exported with wc_ed25519_export_private_only() is not of length ED25519_KEY_SIZE");

            CF_CHECK_NE(priv = wolfCrypt_bignum::Bignum::BinToBignum(ds, priv_bytes, outSize), std::nullopt);

            priv_str = priv->ToTrimmedString();
        }

        /* Export public key */
        {
            std::optional<component::Bignum> pub = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            pub_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_ed25519_export_public(&key, pub_bytes, &outSize), 0);
            CF_ASSERT(outSize = ED25519_PUB_KEY_SIZE,
                    "Public key exported with wc_ed25519_export_public() is not of length ED25519_PUB_KEY_SIZE");

            CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pub_bytes, outSize), std::nullopt);

            pub_x_str = pub->ToTrimmedString();
            pub_y_str = "0";
        }
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed448") ) {
        ed448_key key;

        CF_CHECK_EQ(wc_ed448_make_key(wolfCrypt_detail::GetRNG(), ED448_KEY_SIZE, &key), 0);
        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_ed448_check_key(&key) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_ed448_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_ed448_export_private_only(&key, priv_bytes, &outSize), 0);
            CF_ASSERT(outSize = ED448_KEY_SIZE,
                    "Private key exported with wc_ed448_export_private_only() is not of length ED448_KEY_SIZE");

            CF_CHECK_NE(priv = wolfCrypt_bignum::Bignum::BinToBignum(ds, priv_bytes, outSize), std::nullopt);

            priv_str = priv->ToTrimmedString();
        }

        /* Export public key */
        {
            std::optional<component::Bignum> pub = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            pub_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_ed448_export_public(&key, pub_bytes, &outSize), 0);
            CF_ASSERT(outSize = ED448_PUB_KEY_SIZE,
                    "Public key exported with wc_ed448_export_public() is not of length ED448_PUB_KEY_SIZE");

            CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pub_bytes, outSize), std::nullopt);

            pub_x_str = pub->ToTrimmedString();
            pub_y_str = "0";
        }
    } else if ( op.curveType.Get() == CF_ECC_CURVE("x25519") ) {
        curve25519_key key;

        CF_CHECK_EQ(wc_curve25519_make_key(wolfCrypt_detail::GetRNG(), CURVE25519_KEYSIZE, &key), 0);

        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_curve25519_check_public(key.p.point, CURVE25519_KEYSIZE, EC25519_LITTLE_ENDIAN) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_curve25519_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_curve25519_export_private_raw_ex(&key, priv_bytes, &outSize, EC25519_LITTLE_ENDIAN), 0);
            CF_ASSERT(outSize = CURVE25519_KEYSIZE,
                    "Private key exported with wc_curve25519_export_private_raw_ex() is not of length CURVE25519_KEYSIZE");

            CF_CHECK_NE(priv = wolfCrypt_bignum::Bignum::BinToBignum(ds, priv_bytes, outSize), std::nullopt);

            priv_str = priv->ToTrimmedString();
        }

        /* Export public key */
        {
            std::optional<component::Bignum> pub = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            pub_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_curve25519_export_public_ex(&key, pub_bytes, &outSize, EC25519_LITTLE_ENDIAN), 0);
            CF_ASSERT(outSize = CURVE25519_KEYSIZE,
                    "Public key exported with wc_curve25519_export_public_ex() is not of length CURVE25519_KEYSIZE");

            CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pub_bytes, outSize), std::nullopt);

            pub_x_str = pub->ToTrimmedString();
            pub_y_str = "0";
        }
    } else if ( op.curveType.Get() == CF_ECC_CURVE("x448") ) {
        curve448_key key;

        CF_CHECK_EQ(wc_curve448_make_key(wolfCrypt_detail::GetRNG(), CURVE448_KEY_SIZE, &key), 0);

        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_curve448_check_public(key.p, CURVE448_KEY_SIZE, EC448_BIG_ENDIAN) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_curve448_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_curve448_export_private_raw_ex(&key, priv_bytes, &outSize, EC448_LITTLE_ENDIAN), 0);
            CF_ASSERT(outSize = CURVE448_KEY_SIZE,
                    "Private key exported with wc_curve448_export_private_raw_ex() is not of length CURVE448_KEY_SIZE");

            CF_CHECK_NE(priv = wolfCrypt_bignum::Bignum::BinToBignum(ds, priv_bytes, outSize), std::nullopt);

            priv_str = priv->ToTrimmedString();
        }

        /* Export public key */
        {
            std::optional<component::Bignum> pub = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            pub_bytes = util::malloc(outSize);

            CF_CHECK_EQ(wc_curve448_export_public_ex(&key, pub_bytes, &outSize, EC448_LITTLE_ENDIAN), 0);
            CF_ASSERT(outSize = CURVE448_KEY_SIZE,
                    "Public key exported with wc_curve448_export_public_ex() is not of length CURVE448_KEY_SIZE");

            CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pub_bytes, outSize), std::nullopt);

            pub_x_str = pub->ToTrimmedString();
            pub_y_str = "0";
        }
    } else {
        std::optional<int> curveID;

        /* Initialize */
        {
            CF_CHECK_NE(curveID = wolfCrypt_detail::toCurveID(op.curveType), std::nullopt);

            CF_CHECK_NE(key = wc_ecc_key_new(nullptr), nullptr);
        }

        /* Process */
        {
            CF_CHECK_EQ(wc_ecc_make_key_ex(wolfCrypt_detail::GetRNG(), 0, key, *curveID), 0);

            wolfCrypt_detail::haveAllocFailure = false;
            if ( wc_ecc_check_key(key) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
                CF_ASSERT(0, "Key created with wc_ecc_make_key_ex() fails validation");
            }

            {
                wolfCrypt_bignum::Bignum priv(&key->k, ds);
                wolfCrypt_bignum::Bignum pub_x(key->pubkey.x, ds);
                wolfCrypt_bignum::Bignum pub_y(key->pubkey.y, ds);

                CF_CHECK_NE(priv_str = priv.ToDecString(), std::nullopt);
                CF_CHECK_NE(pub_x_str = pub_x.ToDecString(), std::nullopt);
                CF_CHECK_NE(pub_y_str = pub_y.ToDecString(), std::nullopt);
            }
        }
    }

    /* Finalize */
    {
        ret = {
            std::string(*priv_str),
            { std::string(*pub_x_str), std::string(*pub_y_str) }
        };
    }
end:
    util::free(priv_bytes);
    util::free(pub_bytes);
    CF_NORET(wc_ecc_key_free(key));

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::DH_KeyPair> wolfCrypt::OpDH_GenerateKeyPair(operation::DH_GenerateKeyPair& op) {
    std::optional<component::DH_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    DhKey key;
    uint8_t priv_bytes[8192];
    uint8_t pub_bytes[8192];
    word32 privSz = sizeof(priv_bytes), pubSz = sizeof(pub_bytes);
    std::optional<std::vector<uint8_t>> prime;
    std::optional<std::vector<uint8_t>> base;

    memset(&key, 0, sizeof(key));

    /* Prevent timeouts if wolfCrypt is compiled with --disable-fastmath */
#if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
    CF_CHECK_LT(op.prime.GetSize(), 200);
    CF_CHECK_LT(op.base.GetSize(), 200);
#endif

    CF_CHECK_EQ(wc_InitDhKey(&key), 0);

    CF_CHECK_NE(prime = wolfCrypt_bignum::Bignum::ToBin(ds, op.prime), std::nullopt);
    CF_CHECK_NE(base = wolfCrypt_bignum::Bignum::ToBin(ds, op.base), std::nullopt);
    CF_CHECK_EQ(wc_DhSetKey(&key, prime->data(), prime->size(), base->data(), base->size()), 0);

    CF_CHECK_EQ(wc_DhGenerateKeyPair(&key, wolfCrypt_detail::GetRNG(), priv_bytes, &privSz, pub_bytes, &pubSz), 0);

    {
        std::optional<std::string> pub_str, priv_str;
        wolfCrypt_bignum::Bignum pub(ds), priv(ds);

        CF_CHECK_EQ(mp_read_unsigned_bin(pub.GetPtr(), pub_bytes, pubSz), MP_OKAY);
        CF_CHECK_EQ(mp_read_unsigned_bin(priv.GetPtr(), priv_bytes, privSz), MP_OKAY);

        CF_CHECK_NE(pub_str = pub.ToDecString(), std::nullopt);
        CF_CHECK_NE(priv_str = priv.ToDecString(), std::nullopt);

        ret = {*priv_str, *pub_str};
    }

end:
    wc_FreeDhKey(&key);
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Bignum> wolfCrypt::OpDH_Derive(operation::DH_Derive& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    DhKey key;
    uint8_t agree[8192];
    word32 agreeSz;
    std::optional<std::vector<uint8_t>> prime;
    std::optional<std::vector<uint8_t>> base;
    std::optional<std::vector<uint8_t>> priv;
    std::optional<std::vector<uint8_t>> pub;

    memset(&key, 0, sizeof(key));

    /* Prevent timeouts if wolfCrypt is compiled with --disable-fastmath */
#if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
    CF_CHECK_LT(op.prime.GetSize(), 200);
    CF_CHECK_LT(op.base.GetSize(), 200);
    CF_CHECK_LT(op.pub.GetSize(), 200);
    CF_CHECK_LT(op.priv.GetSize(), 200);
#endif

    CF_CHECK_EQ(wc_InitDhKey(&key), 0);

    CF_CHECK_NE(prime = wolfCrypt_bignum::Bignum::ToBin(ds, op.prime), std::nullopt);
    CF_CHECK_NE(base = wolfCrypt_bignum::Bignum::ToBin(ds, op.base), std::nullopt);
    CF_CHECK_EQ(wc_DhSetKey(&key, prime->data(), prime->size(), base->data(), base->size()), 0);

    CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::ToBin(ds, op.pub), std::nullopt);
    CF_CHECK_NE(priv = wolfCrypt_bignum::Bignum::ToBin(ds, op.priv), std::nullopt);
    CF_CHECK_EQ(wc_DhAgree(&key, agree, &agreeSz, priv->data(), priv->size(), pub->data(), pub->size()), 0);

    {
        std::optional<std::string> derived_str;
        wolfCrypt_bignum::Bignum derived(ds);
        CF_CHECK_EQ(mp_read_unsigned_bin(derived.GetPtr(), agree, agreeSz), MP_OKAY);
        CF_CHECK_NE(derived_str = derived.ToDecString(), std::nullopt);
        if ( *derived_str != "0" ) {
            ret = *derived_str;
        }
    }

end:
    wc_FreeDhKey(&key);
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECDSA_Signature> wolfCrypt::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;

    if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
        return wolfCrypt_detail::OpECDSA_Sign_ed25519(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed448") ) {
        return wolfCrypt_detail::OpECDSA_Sign_ed448(op);
    } else {
        return wolfCrypt_detail::OpECDSA_Sign_Generic(op);
    }
}

std::optional<bool> wolfCrypt::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
        return wolfCrypt_detail::OpECDSA_Verify_ed25519(op);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed448") ) {
        return wolfCrypt_detail::OpECDSA_Verify_ed448(op);
    } else {
        return wolfCrypt_detail::OpECDSA_Verify_Generic(op);
    }
}

std::optional<component::Bignum> wolfCrypt::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
    /* If allocation failures are induced, it is expected
     * that the Bignum class will throw if initialization
     * of the mp_int variable fails. Catch these exceptions
     * and silently proceed.
     */
    try {
#endif

    std::unique_ptr<wolfCrypt_bignum::Operation> opRunner = nullptr;

    wolfCrypt_bignum::BignumCluster bn(ds,
        std::move(wolfCrypt_bignum::Bignum(ds)),
        std::move(wolfCrypt_bignum::Bignum(ds)),
        std::move(wolfCrypt_bignum::Bignum(ds)),
        std::move(wolfCrypt_bignum::Bignum(ds))
    );
    wolfCrypt_bignum::Bignum res(ds);

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);

    /* Save the current values of bn[0..3] */
    CF_NORET(bn.Save());

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Sub>();
            break;
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Mul>();
            break;
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Div>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<wolfCrypt_bignum::ExpMod>();
            break;
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Sqr>();
            break;
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::GCD>();
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Cmp>();
            break;
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Abs>();
            break;
        case    CF_CALCOP("Neg(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Neg>();
            break;
        case    CF_CALCOP("RShift(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::RShift>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::LShift1>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::IsNeg>();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::IsEq>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsOne(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::IsOne>();
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<wolfCrypt_bignum::MulMod>();
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<wolfCrypt_bignum::AddMod>();
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<wolfCrypt_bignum::SubMod>();
            break;
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::SqrMod>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Bit>();
            break;
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::CmpAbs>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::SetBit>();
            break;
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::LCM>();
            break;
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Mod>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::IsOdd>();
            break;
        case    CF_CALCOP("MSB(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::MSB>();
            break;
        case    CF_CALCOP("NumBits(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::NumBits>();
            break;
        case    CF_CALCOP("Set(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Set>();
            break;
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Jacobi>();
            break;
        case    CF_CALCOP("Exp2(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::Exp2>();
            break;
        case    CF_CALCOP("NumLSZeroBits(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::NumLSZeroBits>();
            break;
        case    CF_CALCOP("MulAdd(A,B,C)"):
            opRunner = std::make_unique<wolfCrypt_bignum::MulAdd>();
            break;
        case    CF_CALCOP("CondSet(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::CondSet>();
            break;
        case    CF_CALCOP("Rand()"):
            opRunner = std::make_unique<wolfCrypt_bignum::Rand>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn), true);

    ret = res.ToComponentBignum();

    /* Verify that no parameter (bn[0..3]) was altered during the operation */
    CF_ASSERT(bn.EqualsCache() == true, "Bignum parameters were changed");

#if defined(CRYPTOFUZZ_WOLFCRYPT_ALLOCATION_FAILURES)
    } catch ( std::exception ) { }
#endif

end:

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::Ciphertext> wolfCrypt::OpECIES_Encrypt(operation::ECIES_Encrypt& op) {
    return wolfCrypt_detail::OpECIES_Encrypt_Generic(op);
}

std::optional<component::Cleartext> wolfCrypt::OpECIES_Decrypt(operation::ECIES_Decrypt& op) {
    return wolfCrypt_detail::OpECIES_Decrypt_Generic(op);
}

} /* namespace module */
} /* namespace cryptofuzz */
