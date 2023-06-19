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
#include <wolfssl/wolfcrypt/siphash.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/camellia.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/des3.h>

#include <wolfssl/wolfcrypt/hmac.h>

#include <wolfssl/wolfcrypt/cmac.h>

#include <wolfssl/wolfcrypt/kdf.h>

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

#include "module_internal.h"
#include "bn_ops.h"
#include "ecdsa_generic.h"
#include "ecdsa_448.h"
#include "ecdsa_25519.h"

namespace cryptofuzz {
namespace module {

namespace wolfCrypt_detail {
    int wc_Check(const int ret) {
        CF_ASSERT(ret <= 0, "Unexpected return value");
        return ret;
    }
}

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

    void InitializeSystemRNG(void) {
        const auto cached_disableAllocationFailures = disableAllocationFailures;
        disableAllocationFailures = true;
        CF_ASSERT(wc_InitRng(&wolfCrypt_detail::rng) == 0, "Cannot initialize wolfCrypt RNG");
        disableAllocationFailures = cached_disableAllocationFailures;
    }

    WC_RNG* GetSystemRNG(void) {
        if ( rng.status != 1 ) {
            /* ignore ret */ wc_FreeRng(&rng);
            CF_NORET(InitializeSystemRNG());
            CF_ASSERT(rng.status == 1, "System RNG broken after re-initialization");
        }

        return &rng;
    }
    WC_RNG* GetRNG(void) {
#if defined(WOLF_CRYPTO_CB)
        if ( ds == nullptr ) {
            return GetSystemRNG();
        }

        bool which = false; try { which = ds->Get<bool>(); } catch ( ... ) { }

        return which ? &rng_deterministic : GetSystemRNG();
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
            const size_t a_start = (size_t)preferred;
            const size_t a_end = a_start + n;
            const size_t b_start = (size_t)p.first;
            const size_t b_end = b_start + p.second;

            /* If an existing pointer overlaps with the preferred pointer, revert to normal malloc */
            if ( a_start <= b_end && b_start <= a_end ) {
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

    CF_NORET(wolfCrypt_detail::InitializeSystemRNG());

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
            const bool haveOneShot;
        public:
            Operation(const bool haveOneShot) :
                haveOneShot(haveOneShot)
            { }
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
                if ( haveOneShot ) {
                    try {
                        doOneShot = ds.Get<bool>();
                    } catch ( ... ) { }
                }

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
                Operation<operation::Digest, component::Digest, CTXType>(oneShot != nullptr),
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
                    CF_NORET(freeCTX(&this->ctx));
                }
            }

            std::optional<component::Digest> runOneShot(const Buffer& in, Datasource& ds) override {
                std::optional<component::Digest> ret = std::nullopt;
                std::vector<uint8_t> out(DigestSize);

                CF_CHECK_NE(oneShot, nullptr);

                CF_CHECK_EQ(oneShot(in.GetPtr(&ds), in.GetSize(), out.data()), 0);

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

#if !defined(__i386__)
    Digest<Sha224, WC_SHA224_DIGEST_SIZE, Init_Int<Sha224>, DigestUpdate_Int<Sha224>, DigestFinalize_Int<Sha224>>
        sha224(wc_InitSha224, wc_Sha224Update, wc_Sha224Final, wc_Sha224Free, wc_Sha224Copy, wc_Sha224Hash);
#endif

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

    Digest<wc_Shake, 16, Init_IntParams<wc_Shake>, DigestUpdate_Int<wc_Shake>, DigestFinalize_IntFixedParam<wc_Shake, 16>>
        shake256(wc_InitShake128, wc_Shake128_Update, wc_Shake128_Final, wc_Shake128_Free, wc_Shake128_Copy);
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
#if !defined(__i386__)
            { CF_DIGEST("SHA224"), WC_SHA224_DIGEST_SIZE },
#endif
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

        {
            wolfCrypt_detail::haveAllocFailure = false;
            const auto res = wc_Hash(
                    *hashType,
                    op.cleartext.GetPtr(&ds),
                    op.cleartext.GetSize(),
                    out,
                    hashSize);
            if ( haveAllocFailure == false ) {
                switch ( op.digestType.Get() ) {
                    /* ZD 16119 */
                    case CF_DIGEST("MD2"):
                    case CF_DIGEST("MD4"):
                    case CF_DIGEST("BLAKE2S256"):
                    case CF_DIGEST("BLAKE2B512"):
                        break;
                    default:
                        CF_ASSERT(res == 0, "wc_Hash failed unexpectedly");
                }
            }

            CF_CHECK_EQ(res, 0);
        }

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
        wolfCrypt_detail::haveAllocFailure = false;

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
#if !defined(__i386__)
            case CF_DIGEST("SHA224"):
                ret = wolfCrypt_detail::sha224.Run(op, ds);
                break;
#endif
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
            case CF_DIGEST("SHAKE128"):
                ret = wolfCrypt_detail::shake256.Run(op, ds);
                break;
            case CF_DIGEST("SHAKE256"):
                ret = wolfCrypt_detail::shake512.Run(op, ds);
                break;
            default:
                goto end;
        }

        if ( wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(ret != std::nullopt, "Hashing failed unexpectedly");
        }
    }

end:
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
            WC_CHECK_EQ(wc_InitBlake2b_WithKey(&blake2b, 64, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
        } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S_MAC")) ) {
            WC_CHECK_EQ(wc_InitBlake2s_WithKey(&blake2s, 64, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), 0);
        } else {
            abort();
        }

        parts = util::ToParts(ds, op.cleartext);

        if ( op.digestType.Is(CF_DIGEST("BLAKE2B_MAC")) ) {
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_Blake2bUpdate(&blake2b, part.first, part.second), 0);
            }
        } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S_MAC")) ) {
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_Blake2sUpdate(&blake2s, part.first, part.second), 0);
            }
        }

        if ( op.digestType.Is(CF_DIGEST("BLAKE2B_MAC")) ) {
            WC_CHECK_EQ(wc_Blake2bFinal(&blake2b, out, 64), 0);
        } else if ( op.digestType.Is(CF_DIGEST("BLAKE2S_MAC")) ) {
            WC_CHECK_EQ(wc_Blake2sFinal(&blake2s, out, 64), 0);
        }

        ret = component::MAC(out, 64);
end:
        wolfCrypt_detail::UnsetGlobalDs();
        return ret;
    }

    std::optional<component::MAC> SIPHASH(operation::HMAC& op, const size_t size) {
        std::optional<component::MAC> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        wolfCrypt_detail::SetGlobalDs(&ds);

        SipHash ctx;

        uint8_t out[size];

        bool stream = false;
        try {
            stream = ds.Get<bool>();
        } catch ( ... ) { }

        CF_CHECK_EQ(op.cipher.key.GetSize(), 16);

        if ( stream == false ) {
            WC_CHECK_EQ(wc_SipHash(
                        op.cipher.key.GetPtr(&ds),
                        op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                        out, size), 0);
        } else {
            WC_CHECK_EQ(wc_InitSipHash(&ctx, op.cipher.key.GetPtr(), size), 0);

            util::Multipart parts = util::ToParts(ds, op.cleartext);

            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_SipHashUpdate(&ctx, part.first, part.second), 0);
            }

            WC_CHECK_EQ(wc_SipHashFinal(&ctx, out, size), 0);
        }

        ret = component::MAC(out, size);
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
    } else if ( op.digestType.Is(CF_DIGEST("SIPHASH64")) ) {
        return wolfCrypt_detail::SIPHASH(op, 8);
    } else if ( op.digestType.Is(CF_DIGEST("SIPHASH128")) ) {
        return wolfCrypt_detail::SIPHASH(op, 16);
    }

    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    std::optional<int> hashType;
    std::optional<size_t> hashSize;

    Hmac ctx;
    bool inited = false;
    uint8_t* out = nullptr;
    util::Multipart parts;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(hashType = wolfCrypt_detail::toHashType(op.digestType), std::nullopt);
        CF_CHECK_NE(hashSize = wolfCrypt_detail::toHashSize(op.digestType), std::nullopt);
        out = util::malloc(*hashSize);
        WC_CHECK_EQ(wc_HmacInit(&ctx, nullptr, INVALID_DEVID), 0);
        inited = true;
        WC_CHECK_EQ(wc_HmacSetKey(&ctx, *hashType, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
    }

    /* Process */
    for (const auto& part : parts) {
        WC_CHECK_EQ(wc_HmacUpdate(&ctx, part.first, part.second), 0);
    }

    /* Finalize */
    {
        WC_CHECK_EQ(wc_HmacFinal(&ctx, out), 0);

        ret = component::MAC(out, *hashSize);
    }

end:
    if ( inited == true ) {
        CF_NORET(wc_HmacFree(&ctx));
    }
    util::free(out);

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

namespace wolfCrypt_detail {
    std::optional<component::Ciphertext> OpSymmetricEncrypt_AES_GCM(operation::SymmetricEncrypt& op, Datasource& ds) {
        std::optional<component::Ciphertext> ret = std::nullopt;

        Aes ctx;
        bool inited = false;
        uint8_t* out = nullptr;
        uint8_t* outTag = nullptr;
        bool stream = false;
        try {
            stream = ds.Get<bool>();
        } catch ( ... ) { }

#if !defined(WOLFSSL_AESGCM_STREAM)
        (void)stream;
#endif

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
        if ( stream ) {
            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            inited = true;
            WC_CHECK_EQ(wc_AesGcmInit(&ctx,
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);

            /* Pass AAD */
            {
                const auto parts = util::ToParts(ds, *op.aad);
                for (const auto& part : parts) {
                    WC_CHECK_EQ(wc_AesGcmEncryptUpdate(&ctx,
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
                    WC_CHECK_EQ(wc_AesGcmEncryptUpdate(&ctx,
                                out + pos,
                                part.first, part.second,
                                nullptr, 0), 0);
                    pos += part.second;
                }
            }

            WC_CHECK_EQ(wc_AesGcmEncryptFinal(&ctx, outTag, *op.tagSize), 0);
        } else
#endif
        {
            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            inited = true;
            WC_CHECK_EQ(wc_AesGcmSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_AesGcmEncrypt(
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
        }

        ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()), Buffer(outTag, *op.tagSize));
end:

        util::free(out);
        util::free(outTag);

        if ( inited == true ) {
            CF_NORET(wc_AesFree(&ctx));
        }

        return ret;
    }

    std::optional<component::Cleartext> OpSymmetricDecrypt_AES_GCM(operation::SymmetricDecrypt& op, Datasource& ds) {
        std::optional<component::Cleartext> ret = std::nullopt;

        Aes ctx;
        bool inited = false;
        uint8_t* out = nullptr;
        bool stream = true;
        try {
            stream = ds.Get<bool>();
        } catch ( ... ) { }

#if !defined(WOLFSSL_AESGCM_STREAM)
        (void)stream;
#endif

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
        if ( stream ) {
            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            inited = true;
            WC_CHECK_EQ(wc_AesGcmInit(&ctx,
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);
            /* Pass AAD */
            {
                const auto parts = util::ToParts(ds, *op.aad);
                for (const auto& part : parts) {
                    WC_CHECK_EQ(wc_AesGcmDecryptUpdate(&ctx,
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
                    WC_CHECK_EQ(wc_AesGcmDecryptUpdate(&ctx,
                                out + pos,
                                part.first, part.second,
                                nullptr, 0), 0);
                    pos += part.second;
                }
            }

            WC_CHECK_EQ(wc_AesGcmDecryptFinal(&ctx, op.tag->GetPtr(&ds), op.tag->GetSize()), 0);
        } else
#endif
        {
            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            inited = true;
            WC_CHECK_EQ(wc_AesGcmSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_AesGcmDecrypt(
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
        }

        ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));

end:
        util::free(out);

        if ( inited == true ) {
            CF_NORET(wc_AesFree(&ctx));
        }

        return ret;
    }
} /* namespace wolfCrypt_detail */

std::optional<component::Ciphertext> wolfCrypt::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    uint8_t* out = nullptr;
    uint8_t* outTag = nullptr;

    Aes aes;
    bool aes_inited = false;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
        case CF_CIPHER("AES_192_CBC"):
        case CF_CIPHER("AES_256_CBC"):
        {

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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKey(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);
            WC_CHECK_EQ(wc_AesCbcEncrypt(&aes, out, cleartext.data(), cleartext.size()), 0);

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

            WC_CHECK_EQ(wc_CamelliaSetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds)), 0);
            WC_CHECK_EQ(wc_CamelliaCbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

            ret = component::Ciphertext(Buffer(out, cleartext.size()));
        }
        break;

        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
        {
            ret = wolfCrypt_detail::OpSymmetricEncrypt_AES_GCM(op, ds);
        }
        break;

        case CF_CIPHER("AES_128_CCM"):
        case CF_CIPHER("AES_192_CCM"):
        case CF_CIPHER("AES_256_CCM"):
        {
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesCcmSetKey(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_AesCcmEncrypt(
                        &aes,
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
                WC_CHECK_EQ(wc_ChaCha20Poly1305_Encrypt(
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

                WC_CHECK_EQ(wc_ChaCha20Poly1305_Init(&aead, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), 1), 0);

                {
                    const auto partsAAD = util::ToParts(ds, *op.aad);
                    for (const auto& part : partsAAD) {
                        WC_CHECK_EQ(wc_ChaCha20Poly1305_UpdateAad(&aead, part.first, part.second), 0);
                    }
                }

                {
                    const auto partsData = util::ToParts(ds, op.cleartext);
                    size_t pos = 0;
                    for (const auto& part : partsData) {
                        WC_CHECK_EQ(wc_ChaCha20Poly1305_UpdateData(&aead, part.first, out + pos, part.second), 0);
                        pos += part.second;
                    }
                }

                WC_CHECK_EQ(wc_ChaCha20Poly1305_Final(&aead, outTag), 0);
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

            WC_CHECK_EQ(wc_XChaCha20Poly1305_Encrypt(
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKeyDirect(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCtrEncrypt(&aes, out + outIdx, part.first, part.second), 0);
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKeyDirect(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            /* Note: wc_AesEcbEncrypt does not support streaming */
            WC_CHECK_EQ(wc_AesEcbEncrypt(&aes, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
#endif
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

            WC_CHECK_EQ(wc_AesXtsSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), AES_ENCRYPTION, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesXtsEncrypt(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize(), op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB"):
        case CF_CIPHER("AES_192_CFB"):
        case CF_CIPHER("AES_256_CFB"):
        {
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKeyDirect(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCfbEncrypt(&aes, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB1"):
        case CF_CIPHER("AES_192_CFB1"):
        case CF_CIPHER("AES_256_CFB1"):
        {
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKeyDirect(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCfb1Encrypt(&aes, out + outIdx, part.first, part.second * 8), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_CFB8"):
        case CF_CIPHER("AES_192_CFB8"):
        case CF_CIPHER("AES_256_CFB8"):
        {
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKeyDirect(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCfb8Encrypt(&aes, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("AES_128_OFB"):
        case CF_CIPHER("AES_192_OFB"):
        case CF_CIPHER("AES_256_OFB"):
        {
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKeyDirect(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesOfbEncrypt(&aes, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Ciphertext(Buffer(out, op.cleartext.GetSize()));
        }
        break;

        case CF_CIPHER("RC4"):
        {
            Arc4 ctx;

            out = util::malloc(op.cleartext.GetSize());

            WC_CHECK_EQ(wc_Arc4Init(&ctx, NULL, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_Arc4SetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_Arc4Process(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

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

            WC_CHECK_EQ(wc_Chacha_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_Chacha_SetIV(&ctx, op.cipher.iv.GetPtr(&ds), 0), 0);

            parts = util::ToParts(ds, op.cleartext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_Chacha_Process(&ctx, out + outIdx, part.first, part.second), 0);
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

            WC_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_ENCRYPTION), 0);
            WC_CHECK_EQ(wc_Des_CbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

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

            WC_CHECK_EQ(wc_Des3Init(&ctx, nullptr, -1), 0);
            WC_CHECK_EQ(wc_Des3_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_ENCRYPTION), 0);
            WC_CHECK_EQ(wc_Des3_CbcEncrypt(&ctx, out, cleartext.data(), cleartext.size()), 0);

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

            WC_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_ENCRYPTION), 0);
            WC_CHECK_EQ(wc_Des_EcbEncrypt(&ctx, out, op.cleartext.GetPtr(&ds), op.cleartext.GetSize()), 0);

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
            WC_CHECK_EQ(wc_AesInit(&ctx.aes, NULL, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_GmacSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_GmacUpdate(&ctx,
                        op.cipher.iv.GetPtr(&ds),
                        op.cipher.iv.GetSize(),
                        op.aad->GetPtr(&ds),
                        op.aad->GetSize(),
                        outTag, *op.tagSize), 0);
            CF_NORET(wc_AesFree(&ctx.aes));

            ret = component::Ciphertext(
                    Buffer(op.cleartext.GetPtr(&ds), op.cleartext.GetSize()),
                    Buffer(outTag, *op.tagSize));
        }
        break;
        case CF_CIPHER("AES_128_SIV_CMAC"):
        case CF_CIPHER("AES_192_SIV_CMAC"):
        case CF_CIPHER("AES_256_SIV_CMAC"):
        {
            out = util::malloc(op.cleartext.GetSize());

            outTag = util::malloc(AES_BLOCK_SIZE);

            WC_CHECK_EQ(wc_AesSivEncrypt(
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.aad ? op.aad->GetPtr(&ds) : nullptr, op.aad ? op.aad->GetSize() : 0,
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize(),
                        op.cleartext.GetPtr(&ds), op.cleartext.GetSize(),
                        outTag, out), 0);

            ret = component::Ciphertext(
                    Buffer(out, op.cleartext.GetSize()),
                    Buffer(outTag, AES_BLOCK_SIZE));
        }
        break;
    }

end:
    if ( aes_inited == true ) {
        CF_NORET(wc_AesFree(&aes));
    }
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

    Aes aes;
    bool aes_inited = false;

    switch ( op.cipher.cipherType.Get() ) {
        case CF_CIPHER("AES_128_CBC"):
        case CF_CIPHER("AES_192_CBC"):
        case CF_CIPHER("AES_256_CBC"):
        {
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

            WC_CHECK_EQ(wc_AesInit(&aes, nullptr, INVALID_DEVID), 0);
            aes_inited = true;

            WC_CHECK_EQ(wc_AesSetKey(&aes, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_DECRYPTION), 0);
            WC_CHECK_EQ(wc_AesCbcDecrypt(&aes, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

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

            WC_CHECK_EQ(wc_CamelliaSetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize(),
                        op.cipher.iv.GetPtr(&ds)), 0);
            WC_CHECK_EQ(wc_CamelliaCbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), CAMELLIA_BLOCK_SIZE );
            CF_CHECK_NE(unpaddedCleartext, std::nullopt);
            ret = component::Cleartext(Buffer(*unpaddedCleartext));
        }
        break;

        case CF_CIPHER("AES_128_GCM"):
        case CF_CIPHER("AES_192_GCM"):
        case CF_CIPHER("AES_256_GCM"):
        {
            ret = wolfCrypt_detail::OpSymmetricDecrypt_AES_GCM(op, ds);
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

            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesCcmSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_AesCcmDecrypt(
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
                WC_CHECK_EQ(wc_ChaCha20Poly1305_Decrypt(
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

                WC_CHECK_EQ(wc_ChaCha20Poly1305_Init(&aead, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), 0), 0);

                {
                    const auto partsAAD = util::ToParts(ds, *op.aad);
                    for (const auto& part : partsAAD) {
                        WC_CHECK_EQ(wc_ChaCha20Poly1305_UpdateAad(&aead, part.first, part.second), 0);
                    }
                }

                {
                    const auto partsData = util::ToParts(ds, op.ciphertext);
                    size_t pos = 0;
                    for (const auto& part : partsData) {
                        WC_CHECK_EQ(wc_ChaCha20Poly1305_UpdateData(&aead, part.first, out + pos, part.second), 0);
                        pos += part.second;
                    }

                }

                {
                    uint8_t outTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
                    WC_CHECK_EQ(wc_ChaCha20Poly1305_Final(&aead, outTag), 0);
                    WC_CHECK_EQ(wc_ChaCha20Poly1305_CheckTag(outTag, op.tag->GetPtr(&ds)), 0);
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

            WC_CHECK_EQ(wc_XChaCha20Poly1305_Decrypt(
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

            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCtrEncrypt(&ctx, out + outIdx, part.first, part.second), 0);
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

            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_DECRYPTION), 0);

            /* Note: wc_AesEcbDecrypt does not support streaming */
            WC_CHECK_EQ(wc_AesEcbDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
#endif
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

            WC_CHECK_EQ(wc_AesXtsSetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), AES_DECRYPTION, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesXtsDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize(), op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize()), 0);

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

            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCfbDecrypt(&ctx, out + outIdx, part.first, part.second), 0);
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

            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCfb1Decrypt(&ctx, out + outIdx, part.first, part.second * 8), 0);
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

            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesCfb8Decrypt(&ctx, out + outIdx, part.first, part.second), 0);
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

            WC_CHECK_EQ(wc_AesInit(&ctx, nullptr, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_AesSetKeyDirect(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), op.cipher.iv.GetPtr(&ds), AES_ENCRYPTION), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_AesOfbDecrypt(&ctx, out + outIdx, part.first, part.second), 0);
                outIdx += part.second;
            }

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;

        case CF_CIPHER("RC4"):
        {
            Arc4 ctx;

            out = util::malloc(op.ciphertext.GetSize());

            WC_CHECK_EQ(wc_Arc4Init(&ctx, NULL, INVALID_DEVID), 0);
            WC_CHECK_EQ(wc_Arc4SetKey(
                        &ctx,
                        op.cipher.key.GetPtr(&ds),
                        op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_Arc4Process(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

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

            WC_CHECK_EQ(wc_Chacha_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize()), 0);
            WC_CHECK_EQ(wc_Chacha_SetIV(&ctx, op.cipher.iv.GetPtr(&ds), 0), 0);

            parts = util::ToParts(ds, op.ciphertext);
            for (const auto& part : parts) {
                WC_CHECK_EQ(wc_Chacha_Process(&ctx, out + outIdx, part.first, part.second), 0);
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

            WC_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_DECRYPTION), 0);
            WC_CHECK_EQ(wc_Des_CbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

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

            WC_CHECK_EQ(wc_Des3Init(&ctx, nullptr, -1), 0);
            WC_CHECK_EQ(wc_Des3_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_DECRYPTION), 0);
            WC_CHECK_EQ(wc_Des3_CbcDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

            const auto unpaddedCleartext = util::Pkcs7Unpad( std::vector<uint8_t>(out, out + op.ciphertext.GetSize()), DES_BLOCK_SIZE );
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

            WC_CHECK_EQ(wc_Des_SetKey(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.iv.GetPtr(&ds), DES_DECRYPTION), 0);
            WC_CHECK_EQ(wc_Des_EcbDecrypt(&ctx, out, op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize()), 0);

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

            WC_CHECK_EQ(wc_GmacVerify(
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
        case CF_CIPHER("AES_128_SIV_CMAC"):
        case CF_CIPHER("AES_192_SIV_CMAC"):
        case CF_CIPHER("AES_256_SIV_CMAC"):
        {
            out = util::malloc(op.ciphertext.GetSize());

            CF_CHECK_NE(op.tag, std::nullopt);
            CF_CHECK_EQ(op.tag->GetSize(), AES_BLOCK_SIZE);

            auto tag = op.tag->Get();

            WC_CHECK_EQ(wc_AesSivDecrypt(
                        op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(),
                        op.aad ? op.aad->GetPtr(&ds) : nullptr, op.aad ? op.aad->GetSize() : 0,
                        op.cipher.iv.GetPtr(&ds), op.cipher.iv.GetSize(),
                        op.ciphertext.GetPtr(&ds), op.ciphertext.GetSize(),
                        tag.data(), out), 0);

            ret = component::Cleartext(Buffer(out, op.ciphertext.GetSize()));
        }
        break;
    }

end:
    if ( aes_inited == true ) {
        CF_NORET(wc_AesFree(&aes));
    }
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
        WC_CHECK_EQ(wc_AesCmacGenerate(
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

            WC_CHECK_EQ(wc_InitCmac(&ctx, op.cipher.key.GetPtr(&ds), op.cipher.key.GetSize(), WC_CMAC_AES, nullptr), 0);
        }

        /* Process */
        for (const auto& part : parts) {
            WC_CHECK_EQ(wc_CmacUpdate(&ctx, part.first, part.second), 0);
        }

        /* Finalize */
        {
            WC_CHECK_EQ(wc_CmacFinal(&ctx, out, &outSize), 0);
            ret = component::MAC(out, outSize);
        }
    }

    /* wc_AesCmacVerify return values:
     * 0: Verification succeeded
     * < 0: Internal error (e.g. memory failure)
     * 1: Verification failed
     *
     * Only abort if wc_AesCmacVerify signals explicit
     * verification failure (e.g. returns 1).
     *
     */
    CF_ASSERT(wc_AesCmacVerify(
                    out,
                    outSize,
                    op.cleartext.GetPtr(&ds),
                    op.cleartext.GetSize(),
                    op.cipher.key.GetPtr(&ds),
                    op.cipher.key.GetSize()) != 1,
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

    WC_CHECK_EQ(wc_PKCS12_PBKDF(out,
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

    WC_CHECK_EQ(wc_scrypt(
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

    WC_CHECK_EQ(wc_HKDF(
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

    WC_CHECK_EQ(wc_PRF_TLSv1(out,
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

    WC_CHECK_EQ(wc_X963_KDF(
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

    ed25519_key e25519_key;
    bool e25519_key_inited = false;

    ed448_key e448_key;
    bool e448_key_inited = false;

    curve25519_key c25519_key;
    bool c25519_key_inited = false;

    curve448_key c448_key;
    bool c448_key_inited = false;

    if ( op.curveType.Get() == CF_ECC_CURVE("ed25519") ) {
        WC_CHECK_EQ(wc_ed25519_init(&e25519_key), 0);
        e25519_key_inited = true;

        WC_CHECK_EQ(wc_ed25519_make_key(wolfCrypt_detail::GetRNG(), ED25519_KEY_SIZE, &e25519_key), 0);

        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_ed25519_check_key(&e25519_key) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_ed25519_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            WC_CHECK_EQ(wc_ed25519_export_private_only(&e25519_key, priv_bytes, &outSize), 0);
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

            WC_CHECK_EQ(wc_ed25519_export_public(&e25519_key, pub_bytes, &outSize), 0);
            CF_ASSERT(outSize = ED25519_PUB_KEY_SIZE,
                    "Public key exported with wc_ed25519_export_public() is not of length ED25519_PUB_KEY_SIZE");

            CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pub_bytes, outSize), std::nullopt);

            pub_x_str = pub->ToTrimmedString();
            pub_y_str = "0";
        }
    } else if ( op.curveType.Get() == CF_ECC_CURVE("ed448") ) {
        WC_CHECK_EQ(wc_ed448_init(&e448_key), 0);
        e448_key_inited = true;

        WC_CHECK_EQ(wc_ed448_make_key(wolfCrypt_detail::GetRNG(), ED448_KEY_SIZE, &e448_key), 0);

        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_ed448_check_key(&e448_key) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_ed448_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            WC_CHECK_EQ(wc_ed448_export_private_only(&e448_key, priv_bytes, &outSize), 0);
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

            WC_CHECK_EQ(wc_ed448_export_public(&e448_key, pub_bytes, &outSize), 0);
            CF_ASSERT(outSize = ED448_PUB_KEY_SIZE,
                    "Public key exported with wc_ed448_export_public() is not of length ED448_PUB_KEY_SIZE");

            CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pub_bytes, outSize), std::nullopt);

            pub_x_str = pub->ToTrimmedString();
            pub_y_str = "0";
        }
    } else if ( op.curveType.Get() == CF_ECC_CURVE("x25519") ) {
        WC_CHECK_EQ(wc_curve25519_init(&c25519_key), 0);
        c25519_key_inited = true;

        WC_CHECK_EQ(wc_curve25519_make_key(wolfCrypt_detail::GetRNG(), CURVE25519_KEYSIZE, &c25519_key), 0);

        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_curve25519_check_public(c25519_key.p.point, CURVE25519_KEYSIZE, EC25519_LITTLE_ENDIAN) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_curve25519_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            WC_CHECK_EQ(wc_curve25519_export_private_raw_ex(&c25519_key, priv_bytes, &outSize, EC25519_LITTLE_ENDIAN), 0);
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

            WC_CHECK_EQ(wc_curve25519_export_public_ex(&c25519_key, pub_bytes, &outSize, EC25519_LITTLE_ENDIAN), 0);
            CF_ASSERT(outSize = CURVE25519_KEYSIZE,
                    "Public key exported with wc_curve25519_export_public_ex() is not of length CURVE25519_KEYSIZE");

            CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::BinToBignum(ds, pub_bytes, outSize), std::nullopt);

            pub_x_str = pub->ToTrimmedString();
            pub_y_str = "0";
        }
    } else if ( op.curveType.Get() == CF_ECC_CURVE("x448") ) {
        WC_CHECK_EQ(wc_curve448_init(&c448_key), 0);
        c448_key_inited = true;

        WC_CHECK_EQ(wc_curve448_make_key(wolfCrypt_detail::GetRNG(), CURVE448_KEY_SIZE, &c448_key), 0);

        wolfCrypt_detail::haveAllocFailure = false;
        if ( wc_curve448_check_public(c448_key.p, CURVE448_KEY_SIZE, EC448_BIG_ENDIAN) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
            CF_ASSERT(0, "Key created with wc_curve448_make_key() fails validation");
        }

        /* Export private key */
        {
            std::optional<component::Bignum> priv = std::nullopt;

            outSize = 0;
            try { outSize = ds.Get<uint16_t>(); } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
            priv_bytes = util::malloc(outSize);

            WC_CHECK_EQ(wc_curve448_export_private_raw_ex(&c448_key, priv_bytes, &outSize, EC448_LITTLE_ENDIAN), 0);
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

            WC_CHECK_EQ(wc_curve448_export_public_ex(&c448_key, pub_bytes, &outSize, EC448_LITTLE_ENDIAN), 0);
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
            WC_CHECK_EQ(wc_ecc_make_key_ex(wolfCrypt_detail::GetRNG(), 0, key, *curveID), 0);

            wolfCrypt_detail::haveAllocFailure = false;
            if ( wc_ecc_check_key(key) != 0 && wolfCrypt_detail::haveAllocFailure == false ) {
                CF_ASSERT(0, "Key created with wc_ecc_make_key_ex() fails validation");
            }

            {
                wolfCrypt_bignum::Bignum priv(key->k, ds);
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

    if ( e25519_key_inited == true ) {
        wc_ed25519_free(&e25519_key);
    }

    if ( e448_key_inited == true ) {
        wc_ed448_free(&e448_key);
    }

    if ( c25519_key_inited == true ) {
        wc_curve25519_free(&c25519_key);
    }

    if ( c448_key_inited == true ) {
        wc_curve448_free(&c448_key);
    }

    CF_NORET(wc_ecc_key_free(key));

    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::DH_KeyPair> wolfCrypt::OpDH_GenerateKeyPair(operation::DH_GenerateKeyPair& op) {
    std::optional<component::DH_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    DhKey key;
    uint8_t* priv_bytes = nullptr;
    uint8_t* pub_bytes = nullptr;
    word32 privSz = 8192;
    word32 pubSz = 8192;
    std::optional<std::vector<uint8_t>> prime;
    std::optional<std::vector<uint8_t>> base;

    memset(&key, 0, sizeof(key));

    try {
        privSz = ds.Get<uint16_t>();
        pubSz = ds.Get<uint16_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    priv_bytes = util::malloc(privSz);
    pub_bytes  = util::malloc(pubSz);

    /* Prevent timeouts if wolfCrypt is compiled with --disable-fastmath */
#if !defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)
    CF_CHECK_LT(op.prime.GetSize(), 200);
    CF_CHECK_LT(op.base.GetSize(), 200);
#endif

    WC_CHECK_EQ(wc_InitDhKey(&key), 0);

    CF_CHECK_NE(prime = wolfCrypt_bignum::Bignum::ToBin(ds, op.prime), std::nullopt);
    CF_CHECK_NE(base = wolfCrypt_bignum::Bignum::ToBin(ds, op.base), std::nullopt);
    WC_CHECK_EQ(wc_DhSetKey(&key, prime->data(), prime->size(), base->data(), base->size()), 0);

    WC_CHECK_EQ(wc_DhGenerateKeyPair(&key, wolfCrypt_detail::GetRNG(), priv_bytes, &privSz, pub_bytes, &pubSz), 0);

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
    util::free(priv_bytes);
    util::free(pub_bytes);

    CF_ASSERT(wc_FreeDhKey(&key) == 0, "Cannot free DH key");
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

    /* Prevent timeouts if wolfCrypt is compiled with --disable-fastmath
     * or 8 bit SP math */
#if (!defined(USE_FAST_MATH) && !defined(WOLFSSL_SP_MATH)) || \
    SP_WORD_SIZE==8
    CF_CHECK_LT(op.prime.GetSize(), 200);
    CF_CHECK_LT(op.base.GetSize(), 200);
    CF_CHECK_LT(op.pub.GetSize(), 200);
    CF_CHECK_LT(op.priv.GetSize(), 200);
#endif

    WC_CHECK_EQ(wc_InitDhKey(&key), 0);

    CF_CHECK_NE(prime = wolfCrypt_bignum::Bignum::ToBin(ds, op.prime), std::nullopt);
    CF_CHECK_NE(base = wolfCrypt_bignum::Bignum::ToBin(ds, op.base), std::nullopt);
    WC_CHECK_EQ(wc_DhSetKey(&key, prime->data(), prime->size(), base->data(), base->size()), 0);

    CF_CHECK_NE(pub = wolfCrypt_bignum::Bignum::ToBin(ds, op.pub), std::nullopt);
    CF_CHECK_NE(priv = wolfCrypt_bignum::Bignum::ToBin(ds, op.priv), std::nullopt);
    WC_CHECK_EQ(wc_DhAgree(&key, agree, &agreeSz, priv->data(), priv->size(), pub->data(), pub->size()), 0);

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
    CF_ASSERT(wc_FreeDhKey(&key) == 0, "Cannot free DH key");
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
}

std::optional<component::ECCSI_Signature> wolfCrypt::OpECCSI_Sign(operation::ECCSI_Sign& op) {
    return wolfCrypt_detail::OpECCSI_Sign(op);
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

std::optional<bool> wolfCrypt::OpECCSI_Verify(operation::ECCSI_Verify& op) {
    return wolfCrypt_detail::OpECCSI_Verify(op);
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

std::optional<bool> wolfCrypt::OpDSA_Verify(operation::DSA_Verify& op) {
#if defined(NO_DSA)
    (void)op;
    return std::nullopt;
#else
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    DsaKey key;
    memset(&key, 0, sizeof(key));

    CF_CHECK_EQ(wc_InitDsaKey(&key), 0);

    {
        wolfCrypt_bignum::Bignum p(&key.p, ds);
        CF_CHECK_EQ(p.Set(op.parameters.p.ToString(ds)), true);

        wolfCrypt_bignum::Bignum q(&key.q, ds);
        CF_CHECK_EQ(q.Set(op.parameters.q.ToString(ds)), true);

        wolfCrypt_bignum::Bignum g(&key.g, ds);
        CF_CHECK_EQ(g.Set(op.parameters.g.ToString(ds)), true);

        wolfCrypt_bignum::Bignum pub(&key.y, ds);
        CF_CHECK_EQ(pub.Set(op.pub.ToString(ds)), true);
    }

    {
        auto halfSz = mp_unsigned_bin_size(&key.q);

        std::optional<std::vector<uint8_t>> r, s;
        std::vector<uint8_t> rs;

        /* XXX move these checks to ToBin() */
        CF_CHECK_FALSE(op.signature.first.IsNegative());
        CF_CHECK_FALSE(op.signature.second.IsNegative());

        CF_CHECK_NE(r = wolfCrypt_bignum::Bignum::ToBin(ds, op.signature.first, halfSz), std::nullopt);
        CF_CHECK_NE(s = wolfCrypt_bignum::Bignum::ToBin(ds, op.signature.second, halfSz), std::nullopt);
        rs.insert(rs.end(), r->begin(), r->end());
        rs.insert(rs.end(), s->begin(), s->end());

        auto digest = op.cleartext.Get();
        digest.resize(WC_SHA_DIGEST_SIZE);
        int verified;
        CF_CHECK_EQ(wc_DsaVerify(digest.data(), rs.data(), &key, &verified), 0);

        ret = verified;
    }

end:
    wc_FreeDsaKey(&key);
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
#endif
}

std::optional<component::DSA_Signature> wolfCrypt::OpDSA_Sign(operation::DSA_Sign& op) {
#if defined(NO_DSA)
    (void)op;
    return std::nullopt;
#else
    std::optional<component::DSA_Signature> ret = std::nullopt;
    if ( op.priv.IsZero() ) {
        return std::nullopt;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    DsaKey key1, key2;
    bool key1_inited = false, key2_inited = false;

    uint8_t ber_encoded_key[8192];
    int ber_encoded_size;
    uint8_t* signature = nullptr;

    wolfCrypt_bignum::Bignum p(&key1.p, ds);
    wolfCrypt_bignum::Bignum q(&key1.q, ds);
    wolfCrypt_bignum::Bignum g(&key1.g, ds);
    wolfCrypt_bignum::Bignum priv(&key1.x, ds);
    {
        CF_CHECK_EQ(wc_InitDsaKey(&key1), 0);
        key1_inited = true;

        CF_CHECK_EQ(p.Set(op.parameters.p.ToString(ds)), true);

        CF_CHECK_NE(op.parameters.q.ToTrimmedString(), "0");
        CF_CHECK_NE(op.parameters.q.ToTrimmedString(), "1");
        CF_CHECK_EQ(q.Set(op.parameters.q.ToString(ds)), true);

        CF_CHECK_EQ(g.Set(op.parameters.g.ToString(ds)), true);

        CF_CHECK_EQ(priv.Set(op.priv.ToString(ds)), true);

        CF_CHECK_EQ(mp_exptmod_ex(&key1.g, &key1.x, key1.q.used, &key1.p, &key1.y), MP_OKAY);

        key1.type = DSA_PRIVATE;

        CF_CHECK_GT(ber_encoded_size = wc_DsaKeyToDer(&key1, ber_encoded_key, sizeof(ber_encoded_key)), 0);
    }

    {
        WC_CHECK_EQ(wc_InitDsaKey(&key2), 0);
        key2_inited = true;

        word32 idx = 0;
        WC_CHECK_EQ(wc_DsaPrivateKeyDecode(ber_encoded_key, &idx, &key2, ber_encoded_size), 0);

        auto digest = op.cleartext.Get();
        digest.resize(WC_SHA_DIGEST_SIZE);

        signature = util::malloc(DSA_MAX_SIG_SIZE);

        CF_CHECK_EQ(wc_DsaSign(digest.data(), signature, &key2, &wolfCrypt_detail::rng), 0);

        {
            auto halfSz = mp_unsigned_bin_size(&key2.q);

            if ( DSA_MAX_HALF_SIZE < halfSz ) {
                halfSz = DSA_MAX_HALF_SIZE;
            }

            std::optional<std::string> r_str, s_str, pub_str;
            wolfCrypt_bignum::Bignum r(ds), s(ds);

            CF_CHECK_EQ(mp_read_unsigned_bin(r.GetPtr(), signature, halfSz), MP_OKAY);
            CF_CHECK_EQ(mp_read_unsigned_bin(s.GetPtr(), signature + halfSz, halfSz), MP_OKAY);

            CF_CHECK_NE(r_str = r.ToDecString(), std::nullopt);
            CF_CHECK_NE(s_str = s.ToDecString(), std::nullopt);

            wolfCrypt_bignum::Bignum pub(&key1.y, ds);
            CF_CHECK_NE(pub_str = pub.ToDecString(), std::nullopt);

            ret = component::DSA_Signature({*r_str, *s_str}, *pub_str);
        }
    }
end:
    if ( key1_inited == true ) {
        wc_FreeDsaKey(&key1);
    }
    if ( key2_inited == true ) {
        wc_FreeDsaKey(&key2);
    }
    util::free(signature);
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
#endif
}

std::optional<component::DSA_Parameters> wolfCrypt::OpDSA_GenerateParameters(operation::DSA_GenerateParameters& op) {
#if defined(NO_DSA)
    (void)op;
    return std::nullopt;
#else
    (void)op;
    std::optional<component::DSA_Parameters> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    DsaKey key;
    std::optional<std::string> p_str, q_str, g_str;

    CF_CHECK_EQ(wc_InitDsaKey(&key), 0);
    CF_CHECK_EQ(wc_MakeDsaParameters(wolfCrypt_detail::GetRNG(), 1024, &key), 0);

    {
        wolfCrypt_bignum::Bignum p(&key.p, ds);
        wolfCrypt_bignum::Bignum q(&key.q, ds);
        wolfCrypt_bignum::Bignum g(&key.g, ds);

        CF_CHECK_NE(p_str = p.ToDecString(), std::nullopt);
        CF_CHECK_NE(q_str = q.ToDecString(), std::nullopt);
        CF_CHECK_NE(g_str = g.ToDecString(), std::nullopt);

        ret = { *p_str, *q_str, *g_str };
    }
end:
    wc_FreeDsaKey(&key);
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
#endif
}

std::optional<component::Bignum> wolfCrypt::OpDSA_PrivateToPublic(operation::DSA_PrivateToPublic& op) {
#if defined(NO_DSA)
    (void)op;
    return std::nullopt;
#else
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    wolfCrypt_bignum::Bignum g(ds);
    wolfCrypt_bignum::Bignum p(ds);
    wolfCrypt_bignum::Bignum priv(ds);
    wolfCrypt_bignum::Bignum pub(ds);
    CF_CHECK_TRUE(priv.Set(op.g.ToString(ds)));
    CF_CHECK_TRUE(priv.Set(op.p.ToString(ds)));
    CF_CHECK_TRUE(priv.Set(op.priv.ToString(ds)));
    CF_CHECK_EQ(mp_exptmod(g.GetPtr(), priv.GetPtr(), p.GetPtr(), pub.GetPtr()), MP_OKAY);

end:
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
#endif
}

std::optional<component::DSA_KeyPair> wolfCrypt::OpDSA_GenerateKeyPair(operation::DSA_GenerateKeyPair& op) {
#if defined(NO_DSA)
    (void)op;
    return std::nullopt;
#else
    std::optional<component::DSA_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    wolfCrypt_detail::SetGlobalDs(&ds);

    DsaKey key;
    std::optional<std::string> pub_str, priv_str;;

    memset(&key, 0, sizeof(key));

    CF_CHECK_EQ(wc_InitDsaKey(&key), 0);

    {
        const auto p = util::DecToHex(op.p.ToTrimmedString());
        const auto q = util::DecToHex(op.q.ToTrimmedString());
        const auto g = util::DecToHex(op.g.ToTrimmedString());
        CF_CHECK_EQ(wc_DsaImportParamsRaw(&key, p.c_str(), q.c_str(), g.c_str()), 0);
    }

    CF_CHECK_EQ(wc_MakeDsaKey(wolfCrypt_detail::GetRNG(), &key), 0);

    {
        wolfCrypt_bignum::Bignum pub(&key.y, ds);
        wolfCrypt_bignum::Bignum priv(&key.x, ds);

        CF_CHECK_NE(pub_str = pub.ToDecString(), std::nullopt);
        CF_CHECK_NE(priv_str = priv.ToDecString(), std::nullopt);
    }

    /* Finalize */
    {
        ret = { std::string(*priv_str), std::string(*pub_str) };
    }

end:
    wc_FreeDsaKey(&key);
    wolfCrypt_detail::UnsetGlobalDs();

    return ret;
#endif
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

    CF_NORET(res.Randomize());

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
        case    CF_CALCOP("CondSet(A,B)"):
            opRunner = std::make_unique<wolfCrypt_bignum::CondSet>();
            break;
        case    CF_CALCOP("Rand()"):
            opRunner = std::make_unique<wolfCrypt_bignum::Rand>();
            break;
        case    CF_CALCOP("Zero()"):
            opRunner = std::make_unique<wolfCrypt_bignum::Zero>();
            break;
        case    CF_CALCOP("Prime()"):
            opRunner = std::make_unique<wolfCrypt_bignum::Prime>();
            break;
        case    CF_CALCOP("IsPrime(A)"):
            opRunner = std::make_unique<wolfCrypt_bignum::IsPrime>();
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

std::optional<component::ECC_Point> wolfCrypt::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    return wolfCrypt_detail::OpECC_Point_Add(op);
}

std::optional<component::ECC_Point> wolfCrypt::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    return wolfCrypt_detail::OpECC_Point_Mul(op);
}

std::optional<component::ECC_Point> wolfCrypt::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    return wolfCrypt_detail::OpECC_Point_Dbl(op);
}

std::optional<bool> wolfCrypt::OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) {
    return wolfCrypt_detail::OpECC_Point_Cmp(op);
}

std::optional<component::Secret> wolfCrypt::OpECDH_Derive(operation::ECDH_Derive& op) {
    return wolfCrypt_detail::OpECDH_Derive(op);
}

} /* namespace module */
} /* namespace cryptofuzz */
