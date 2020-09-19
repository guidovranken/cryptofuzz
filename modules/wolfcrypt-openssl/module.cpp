#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
#include "bn_ops.h"
extern "C" {
#include <wolfssl/openssl/hmac.h>
}
#include "module_internal.h"

namespace cryptofuzz {
namespace module {

wolfCrypt_OpenSSL::wolfCrypt_OpenSSL(void) :
    Module("wolfCrypt-OpenSSL") {
}

namespace wolfCrypt_OpenSSL_detail {
    const EVP_MD* toEVPMD(const component::DigestType& digestType) {
        using fuzzing::datasource::ID;

        static const std::map<uint64_t, const EVP_MD*> LUT = {
#if defined(CRYPTOFUZZ_BORINGSSL)
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
            { CF_DIGEST("SHA512-256"), EVP_sha512_256() },
#elif defined(CRYPTOFUZZ_LIBRESSL)
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
            { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
            { CF_DIGEST("SM3"), EVP_sm3() },
            { CF_DIGEST("GOST-R-34.11-94"), EVP_gostr341194() },
            { CF_DIGEST("GOST-28147-89"), EVP_gost2814789imit() },
            { CF_DIGEST("STREEBOG-256"), EVP_streebog256() },
            { CF_DIGEST("STREEBOG-512"), EVP_streebog512() },
#elif defined(CRYPTOFUZZ_OPENSSL_102)
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("MD2"), EVP_md2() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("MDC2"), EVP_mdc2() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
            { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
#elif defined(CRYPTOFUZZ_OPENSSL_110)
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("MD2"), EVP_md2() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
            { CF_DIGEST("MDC2"), EVP_mdc2() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
            { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
            { CF_DIGEST("BLAKE2B512"), EVP_blake2b512() },
            { CF_DIGEST("BLAKE2S256"), EVP_blake2s256() },
#elif defined(CRYPTOFUZZ_WOLFCRYPT)
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("MDC2"), EVP_mdc2() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
#if 0
            { CF_DIGEST("MDC2"), EVP_mdc2() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
            { CF_DIGEST("SHA3-224"), EVP_sha3_224() },
            { CF_DIGEST("SHA3-256"), EVP_sha3_256() },
            { CF_DIGEST("SHA3-384"), EVP_sha3_384() },
            { CF_DIGEST("SHA3-512"), EVP_sha3_512() },
#endif
#else
            { CF_DIGEST("SHA1"), EVP_sha1() },
            { CF_DIGEST("SHA224"), EVP_sha224() },
            { CF_DIGEST("SHA256"), EVP_sha256() },
            { CF_DIGEST("SHA384"), EVP_sha384() },
            { CF_DIGEST("SHA512"), EVP_sha512() },
            { CF_DIGEST("MD2"), EVP_md2() },
            { CF_DIGEST("MD4"), EVP_md4() },
            { CF_DIGEST("MD5"), EVP_md5() },
            { CF_DIGEST("MD5_SHA1"), EVP_md5_sha1() },
            { CF_DIGEST("MDC2"), EVP_mdc2() },
            { CF_DIGEST("RIPEMD160"), EVP_ripemd160() },
            { CF_DIGEST("WHIRLPOOL"), EVP_whirlpool() },
            { CF_DIGEST("SM3"), EVP_sm3() },
            { CF_DIGEST("BLAKE2B512"), EVP_blake2b512() },
            { CF_DIGEST("BLAKE2S256"), EVP_blake2s256() },
            { CF_DIGEST("SHAKE128"), EVP_shake128() },
            { CF_DIGEST("SHAKE256"), EVP_shake256() },
            { CF_DIGEST("SHA3-224"), EVP_sha3_224() },
            { CF_DIGEST("SHA3-256"), EVP_sha3_256() },
            { CF_DIGEST("SHA3-384"), EVP_sha3_384() },
            { CF_DIGEST("SHA3-512"), EVP_sha3_512() },
            { CF_DIGEST("SHA512-224"), EVP_sha512_224() },
            { CF_DIGEST("SHA512-256"), EVP_sha512_256() },
#endif
        };

        if ( LUT.find(digestType.Get()) == LUT.end() ) {
            return nullptr;
        }

        return LUT.at(digestType.Get());
    }
}

std::optional<component::Digest> wolfCrypt_OpenSSL::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    util::Multipart parts;

    CF_EVP_MD_CTX ctx(ds);
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        CF_CHECK_NE(md = wolfCrypt_OpenSSL_detail::toEVPMD(op.digestType), nullptr);
        CF_CHECK_EQ(EVP_DigestInit_ex(ctx.GetPtr(), md, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestUpdate(ctx.GetPtr(), part.first, part.second), 1);
    }

    /* Finalize */
    {
        unsigned int len = -1;
        unsigned char md[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(EVP_DigestFinal_ex(ctx.GetPtr(), md, &len), 1);

        ret = component::Digest(md, len);
    }

end:
    return ret;
}

namespace wolfCrypt_OpenSSL_detail {
std::optional<component::MAC> OpHMAC_EVP(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    CF_EVP_MD_CTX ctx(ds);
    const EVP_MD* md = nullptr;
    EVP_PKEY *pkey = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);

        CF_CHECK_NE(md = wolfCrypt_OpenSSL_detail::toEVPMD(op.digestType), nullptr);
        CF_CHECK_NE(pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr, op.cipher.key.GetPtr(), op.cipher.key.GetSize()), nullptr);
        CF_CHECK_EQ(EVP_DigestSignInit(ctx.GetPtr(), nullptr, md, nullptr, pkey), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(EVP_DigestSignUpdate(ctx.GetPtr(), part.first, part.second), 1);
    }

    /* Finalize */
    {
        size_t len = -1;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(EVP_DigestSignFinal(ctx.GetPtr(), out, &len), 1);

        ret = component::MAC(out, len);
    }

end:
    EVP_PKEY_free(pkey);

    return ret;
}

std::optional<component::MAC> OpHMAC_HMAC(operation::HMAC& op, Datasource& ds) {
    std::optional<component::MAC> ret = std::nullopt;

    util::Multipart parts;

    CF_HMAC_CTX ctx(ds);
    const EVP_MD* md = nullptr;

    /* Initialize */
    {
        parts = util::ToParts(ds, op.cleartext);
        /* TODO remove ? */
        HMAC_CTX_reset(ctx.GetPtr());
        CF_CHECK_NE(md = toEVPMD(op.digestType), nullptr);
        CF_CHECK_EQ(HMAC_Init_ex(ctx.GetPtr(), op.cipher.key.GetPtr(), op.cipher.key.GetSize(), md, nullptr), 1);
    }

    /* Process */
    for (const auto& part : parts) {
        CF_CHECK_EQ(HMAC_Update(ctx.GetPtr(), part.first, part.second), 1);
    }

    /* Finalize */
    {
        unsigned int len = -1;
        uint8_t out[EVP_MAX_MD_SIZE];
        CF_CHECK_EQ(HMAC_Final(ctx.GetPtr(), out, &len), 1);

        ret = component::MAC(out, len);
    }

end:
    return ret;
}
}

std::optional<component::MAC> wolfCrypt_OpenSSL::OpHMAC(operation::HMAC& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

#if !defined(CRYPTOFUZZ_WOLFCRYPT)
    if (    op.digestType.Get() == CF_DIGEST("SIPHASH64") ||
            op.digestType.Get() == CF_DIGEST("SIPHASH128") ) {
        /* Not HMAC but invoking SipHash here anyway due to convenience. */
        return OpenSSL_detail::SipHash(op);
    }
#endif

    bool useEVP = true;
    try {
        useEVP = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) {
    }

    if ( useEVP == true ) {
#if !defined(CRYPTOFUZZ_BORINGSSL)
        return wolfCrypt_OpenSSL_detail::OpHMAC_EVP(op, ds);
#else
        return wolfCrypt_OpenSSL_detail::OpHMAC_HMAC(op, ds);
#endif
    } else {
#if !defined(CRYPTOFUZZ_OPENSSL_102)
        return wolfCrypt_OpenSSL_detail::OpHMAC_HMAC(op, ds);
#else
        return wolfCrypt_OpenSSL_detail::OpHMAC_EVP(op, ds);
#endif
    }

    return {};
}

std::optional<component::Bignum> wolfCrypt_OpenSSL::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    OpenSSL_bignum::BN_CTX ctx(ds);
    OpenSSL_bignum::BignumCluster bn(ds,
        OpenSSL_bignum::Bignum(ds),
        OpenSSL_bignum::Bignum(ds),
        OpenSSL_bignum::Bignum(ds),
        OpenSSL_bignum::Bignum(ds));
    OpenSSL_bignum::Bignum res(ds);
    std::unique_ptr<OpenSSL_bignum::Operation> opRunner = nullptr;

    CF_CHECK_EQ(res.New(), true);
    CF_CHECK_EQ(bn.New(0), true);
    CF_CHECK_EQ(bn.New(1), true);
    CF_CHECK_EQ(bn.New(2), true);
    CF_CHECK_EQ(bn.New(3), true);

    CF_CHECK_EQ(res.Set("0"), true);
    CF_CHECK_EQ(bn.Set(0, op.bn0.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(1, op.bn1.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(2, op.bn2.ToString(ds)), true);
    CF_CHECK_EQ(bn.Set(3, op.bn3.ToString(ds)), true);

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Add>();
            break;
        case    CF_CALCOP("Sub(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sub>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Mul(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mul>();
            break;
#endif
        case    CF_CALCOP("Mod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod>();
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::ExpMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Sqr(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sqr>();
            break;
#endif
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("GCD(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::GCD>();
            break;
#endif
        case    CF_CALCOP("AddMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::AddMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("SubMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::SubMod>();
            break;
#endif
        case    CF_CALCOP("MulMod(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::MulMod>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("SqrMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SqrMod>();
            break;
#endif
        case    CF_CALCOP("InvMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::InvMod>();
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Cmp>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Div(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Div>();
            break;
#endif
        case    CF_CALCOP("IsPrime(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsPrime>();
            break;
        case    CF_CALCOP("Sqrt(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Sqrt>();
            break;
        case    CF_CALCOP("IsNeg(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsNeg>();
            break;
        case    CF_CALCOP("IsEq(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsEq>();
            break;
        case    CF_CALCOP("IsEven(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsEven>();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsOdd>();
            break;
        case    CF_CALCOP("IsZero(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsZero>();
            break;
        case    CF_CALCOP("IsOne(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsOne>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Jacobi(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Jacobi>();
            break;
#endif
#if !defined(CRYPTOFUZZ_BORINGSSL) && !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Mod_NIST_192(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_192>();
            break;
        case    CF_CALCOP("Mod_NIST_224(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_224>();
            break;
        case    CF_CALCOP("Mod_NIST_256(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_256>();
            break;
        case    CF_CALCOP("Mod_NIST_384(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_384>();
            break;
        case    CF_CALCOP("Mod_NIST_521(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mod_NIST_521>();
            break;
#endif
        case    CF_CALCOP("SqrtMod(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SqrtMod>();
            break;
#if defined(CRYPTOFUZZ_BORINGSSL)
        case    CF_CALCOP("LCM(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::LCM>();
            break;
#endif
        case    CF_CALCOP("Exp(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Exp>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("Abs(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::Abs>();
            break;
#endif
        case    CF_CALCOP("RShift(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::RShift>();
            break;
        case    CF_CALCOP("LShift1(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::LShift1>();
            break;
        case    CF_CALCOP("SetBit(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::SetBit>();
            break;
        case    CF_CALCOP("ClearBit(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::ClearBit>();
            break;
        case    CF_CALCOP("Bit(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Bit>();
            break;
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("CmpAbs(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::CmpAbs>();
            break;
#endif
#if !defined(CRYPTOFUZZ_WOLFCRYPT)
        case    CF_CALCOP("ModLShift(A,B,C)"):
            opRunner = std::make_unique<OpenSSL_bignum::ModLShift>();
            break;
#endif
        case    CF_CALCOP("IsPow2(A)"):
            opRunner = std::make_unique<OpenSSL_bignum::IsPow2>();
            break;
        case    CF_CALCOP("Mask(A,B)"):
            opRunner = std::make_unique<OpenSSL_bignum::Mask>();
            break;
    }

    CF_CHECK_NE(opRunner, nullptr);
    CF_CHECK_EQ(opRunner->Run(ds, res, bn, ctx), true);

    ret = res.ToComponentBignum();

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
