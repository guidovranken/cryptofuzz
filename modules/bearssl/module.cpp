#include "module.h"
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptofuzz/repository.h>
#include <sstream>
#include <algorithm>

extern "C" {
    #include <bearssl.h>
}

namespace cryptofuzz {
namespace module {

namespace BearSSL_detail {
    static br_hmac_drbg_context rng;

    template <class Context, size_t Size>
    std::optional<component::Digest> digest(
            void(*init)(Context*),
            void(*update)(Context*, const void*, size_t),
            void(*finish)(const Context*, void*),
            const component::Cleartext& in,
            Datasource& ds
        )
    {
        std::optional<component::Digest> ret = std::nullopt;

        Context ctx;
        uint8_t* out = util::malloc(Size);

        init(&ctx);

        const auto parts = util::ToParts(ds, in);
        for (const auto& part : parts) {
            update(&ctx, part.first, part.second);
        }

        finish(&ctx, out);

        ret = component::Digest(out, Size);

        util::free(out);

        return ret;
    }

    const br_hash_class* To_br_hash_class(const component::DigestType& digestType) {
        switch ( digestType.Get() ) {
            case    CF_DIGEST("MD5"):
                return &br_md5_vtable;
            case    CF_DIGEST("SHA1"):
                return &br_sha1_vtable;
            case    CF_DIGEST("MD5_SHA1"):
                return &br_md5sha1_vtable;
            case    CF_DIGEST("SHA224"):
                return &br_sha224_vtable;
            case    CF_DIGEST("SHA256"):
                return &br_sha256_vtable;
            case    CF_DIGEST("SHA384"):
                return &br_sha384_vtable;
            case    CF_DIGEST("SHA512"):
                return &br_sha512_vtable;
            default:
                return nullptr;
        }
    }

    static bool EncodeBignum(const std::string s, uint8_t* out, const size_t maxSize, const bool reverse = false) {
        std::vector<uint8_t> v;
        boost::multiprecision::cpp_int c(s);
        boost::multiprecision::export_bits(c, std::back_inserter(v), 8);
        if ( v.size() > maxSize ) {
            return false;
        }
        const auto diff = maxSize - v.size();

        memset(out, 0, maxSize);
        memcpy(out + diff, v.data(), v.size());

        if ( reverse == true ) {
            std::reverse(out, out + maxSize);
        }

        return true;
    }

    static std::string toString(const uint8_t* data, const size_t size) {
        boost::multiprecision::cpp_int i;
        boost::multiprecision::import_bits(i, data, data + size);

        std::stringstream ss;
        ss << i;

        if ( ss.str().empty() ) {
            return "0";
        } else {
            return ss.str();
        }
    }

    int toCurveID(const component::CurveType& curveType) {
        static const std::map<uint64_t, int> LUT = {
            { CF_ECC_CURVE("brainpool256r1"), BR_EC_brainpoolP256r1},
            { CF_ECC_CURVE("brainpool384r1"), BR_EC_brainpoolP384r1},
            { CF_ECC_CURVE("brainpool512r1"), BR_EC_brainpoolP512r1},
            { CF_ECC_CURVE("x25519"), BR_EC_curve25519},
#if 0
            { CF_ECC_CURVE("x448"), BR_EC_curve448},
#endif
            { CF_ECC_CURVE("secp160k1"), BR_EC_secp160k1},
            { CF_ECC_CURVE("secp160r1"), BR_EC_secp160r1},
            { CF_ECC_CURVE("secp160r2"), BR_EC_secp160r2},
            { CF_ECC_CURVE("secp192k1"), BR_EC_secp192k1},
            { CF_ECC_CURVE("secp192r1"), BR_EC_secp192r1},
            { CF_ECC_CURVE("secp224k1"), BR_EC_secp224k1},
            { CF_ECC_CURVE("secp224r1"), BR_EC_secp224r1},
            { CF_ECC_CURVE("secp256k1"), BR_EC_secp256k1},
            { CF_ECC_CURVE("secp256r1"), BR_EC_secp256r1},
            { CF_ECC_CURVE("secp384r1"), BR_EC_secp384r1},
            { CF_ECC_CURVE("secp521r1"), BR_EC_secp521r1},
            { CF_ECC_CURVE("sect163k1"), BR_EC_sect163k1},
            { CF_ECC_CURVE("sect163r1"), BR_EC_sect163r1},
            { CF_ECC_CURVE("sect163r2"), BR_EC_sect163r2},
            { CF_ECC_CURVE("sect193r1"), BR_EC_sect193r1},
            { CF_ECC_CURVE("sect193r2"), BR_EC_sect193r2},
            { CF_ECC_CURVE("sect233k1"), BR_EC_sect233k1},
            { CF_ECC_CURVE("sect233r1"), BR_EC_sect233r1},
            { CF_ECC_CURVE("sect239k1"), BR_EC_sect239k1},
            { CF_ECC_CURVE("sect283k1"), BR_EC_sect283k1},
            { CF_ECC_CURVE("sect283r1"), BR_EC_sect283r1},
            { CF_ECC_CURVE("sect409k1"), BR_EC_sect409k1},
            { CF_ECC_CURVE("sect409r1"), BR_EC_sect409r1},
            { CF_ECC_CURVE("sect571k1"), BR_EC_sect571k1},
            { CF_ECC_CURVE("sect571r1"), BR_EC_sect571r1},
        };

        if ( LUT.find(curveType.Get()) == LUT.end() ) {
            return -1;
        }

        return LUT.at(curveType.Get());
    }

    component::BignumPair EncodePubkey(const component::CurveType& curveType, const uint8_t* data, const size_t size) {
        switch ( curveType.Get() ) {
            case    CF_ECC_CURVE("x25519"):
                {
                    CF_ASSERT(size == 32, "x25519 pubkey is not 32 bytes");
                    return {
                        BearSSL_detail::toString(data, 32),
                        "0" };
                }
                break;
            default:
                {
                    if ( (size % 2) != 1 || data[0] != 0x04 ) {
                        abort();
                    }
                    size_t halfSize = (size - 1) / 2;

                    return {
                        BearSSL_detail::toString(data + 1, halfSize),
                        BearSSL_detail::toString(data + 1 + halfSize, halfSize) };
                }
        }
    }
	
    const br_block_ctrcbc_class* Get_br_block_ctrcbc_class(Datasource& ds) {
        try {
            switch ( ds.Get<uint8_t>() ) {
                case    0:
                    return &br_aes_big_ctrcbc_vtable;
                case    1:
                    return &br_aes_small_ctrcbc_vtable;
                case    2:
                    return &br_aes_ct_ctrcbc_vtable;
                case    3:
                    return &br_aes_ct64_ctrcbc_vtable;
                case    4:
                    {
                        const auto ret = br_aes_x86ni_ctrcbc_get_vtable();
                        if ( ret == nullptr ) {
                            goto end;
                        }
                        return ret;
                    }
                    break;
                default:
                        goto end;
            }
        } catch ( ... ) { }

end:
        return &br_aes_big_ctrcbc_vtable;
    }

    const br_ec_impl* Get_br_ec_impl(Datasource& ds, const component::CurveType& curveType) {
        try {
            switch ( ds.Get<uint8_t>() ) {
                case    0:
                    switch ( curveType.Get() ) {
                        case    CF_ECC_CURVE("secp256r1"):
                        case    CF_ECC_CURVE("secp384r1"):
                        case    CF_ECC_CURVE("secp521r1"):
                            return &br_ec_prime_i15;
                        default:
                            goto end;
                    }
                case    1:
                    switch ( curveType.Get() ) {
                        case    CF_ECC_CURVE("secp256r1"):
                        case    CF_ECC_CURVE("secp384r1"):
                        case    CF_ECC_CURVE("secp521r1"):
                            return &br_ec_prime_i31;
                        default:
                            goto end;
                    }
                case    2:
                    CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("secp256r1"));
                    return &br_ec_p256_m15;
                case    3:
                    CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("secp256r1"));
                    return &br_ec_p256_m31;
                case    4:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("secp256r1"));
                        const auto ret = br_ec_p256_m62_get();
                        CF_CHECK_NE(ret, nullptr);
                        return ret;
                    }
                    break;
                case    5:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("secp256r1"));
                        const auto ret = br_ec_p256_m64_get();
                        CF_CHECK_NE(ret, nullptr);
                        return ret;
                    }
                    break;
                case    6:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("x25519"));
                        const auto ret = br_ec_c25519_m62_get();
                        CF_CHECK_NE(ret, nullptr);
                        return ret;
                    }
                    break;
                case    7:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("x25519"));
                        const auto ret = br_ec_c25519_m64_get();
                        CF_CHECK_NE(ret, nullptr);
                        return ret;
                    }
                    break;
                case    8:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("x25519"));
                        return &br_ec_c25519_i15;
                    }
                    break;
                case    9:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("x25519"));
                        return &br_ec_c25519_i31;
                    }
                    break;
                case    10:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("x25519"));
                        return &br_ec_c25519_m15;
                    }
                    break;
                case    11:
                    {
                        CF_CHECK_EQ(curveType.Get(), CF_ECC_CURVE("x25519"));
                        return &br_ec_c25519_m31;
                    }
                    break;
                default:
                        goto end;
            }
        } catch ( ... ) { }

end:
        return br_ec_get_default();
    }

    br_chacha20_run Get_br_chacha20_run(Datasource& ds) {
        try {
            switch ( ds.Get<uint8_t>() ) {
                case    0:
                    return &br_chacha20_ct_run;
                case    1:
                    {
                        const auto ret = br_chacha20_sse2_get();
                        if ( ret == nullptr ) {
                            goto end;
                        }
                        return ret;
                    }
                    break;
                default:
                        goto end;
            }
        } catch ( ... ) { }

end:
        return &br_chacha20_ct_run;
    }

    br_ecdsa_sign Get_br_ecdsa_sign(Datasource& ds) {
        try {
            switch ( ds.Get<uint8_t>() ) {
                case    0:
                    return &br_ecdsa_i31_sign_raw;
                case    1:
                    return &br_ecdsa_i15_sign_raw;
                default:
                        goto end;
            }
        } catch ( ... ) { }

end:
        return &br_ecdsa_i31_sign_raw;
    }

    br_ecdsa_vrfy Get_br_ecdsa_vrfy(Datasource& ds) {
        try {
            switch ( ds.Get<uint8_t>() ) {
                case    0:
                    return &br_ecdsa_i31_vrfy_raw;
                case    1:
                    return &br_ecdsa_i15_vrfy_raw;
                default:
                        goto end;
            }
        } catch ( ... ) { }

end:
        return &br_ecdsa_i31_vrfy_raw;
    }

    bool IsValidPrivateKey(const component::Bignum& priv, const component::CurveType& curveType) {
        if ( curveType.Is(CF_ECC_CURVE("x25519")) ) {
            return true;
        }

        const auto s = priv.ToTrimmedString();
        if ( s == "0" ) {
            return false;
        }

        const auto order = repository::ECC_CurveToOrder(curveType.Get());
        if ( order == std::nullopt ) {
            return false;
        }

        boost::multiprecision::cpp_int priv_cpp_int(s);
        boost::multiprecision::cpp_int order_cpp_int(*order);

        return priv_cpp_int < order_cpp_int;
    }
}

BearSSL::BearSSL(void) :
    Module("BearSSL") {
        /* noret */ br_hmac_drbg_init(&BearSSL_detail::rng, &br_sha256_vtable, NULL, 0);
        br_prng_seeder seeder = br_prng_seeder_system(NULL);
        if ( seeder == 0 ) {
            printf("Cannot initialize PRNG seeder\n");
            abort();
        }
        if ( seeder(&BearSSL_detail::rng.vtable) == 0 ) {
            printf("Cannot seed PRNG\n");
            abort();
        }
}


std::optional<component::Digest> BearSSL::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    switch ( op.digestType.Get() ) {
        case    CF_DIGEST("MD5"):
            return BearSSL_detail::digest<br_md5_context, br_md5_SIZE>(br_md5_init, br_md5_update, br_md5_out, op.cleartext, ds);
        case    CF_DIGEST("MD5_SHA1"):
            return BearSSL_detail::digest<br_md5sha1_context, br_md5sha1_SIZE>(br_md5sha1_init, br_md5sha1_update, br_md5sha1_out, op.cleartext, ds);
        case    CF_DIGEST("SHA1"):
            return BearSSL_detail::digest<br_sha1_context, br_sha1_SIZE>(br_sha1_init, br_sha1_update, br_sha1_out, op.cleartext, ds);
        case    CF_DIGEST("SHA224"):
            return BearSSL_detail::digest<br_sha224_context, br_sha224_SIZE>(br_sha224_init, br_sha224_update, br_sha224_out, op.cleartext, ds);
        case    CF_DIGEST("SHA256"):
            return BearSSL_detail::digest<br_sha256_context, br_sha256_SIZE>(br_sha256_init, br_sha256_update, br_sha256_out, op.cleartext, ds);
        case    CF_DIGEST("SHA384"):
            return BearSSL_detail::digest<br_sha384_context, br_sha384_SIZE>(br_sha384_init, br_sha384_update, br_sha384_out, op.cleartext, ds);
        case    CF_DIGEST("SHA512"):
            return BearSSL_detail::digest<br_sha512_context, br_sha512_SIZE>(br_sha512_init, br_sha512_update, br_sha512_out, op.cleartext, ds);
        case    CF_DIGEST("SHAKE128"):
            {
                uint8_t out[16];
                br_shake_context ctx;
                const auto parts = util::ToParts(ds, op.cleartext);

                /* noret */ br_shake_init(&ctx, 128);
                for (const auto& part : parts) {
                    /* noret */ br_shake_inject(&ctx, part.first, part.second);
                }
                /* noret */ br_shake_flip(&ctx);
                /* noret */ br_shake_produce(&ctx, out, 16);

                ret = component::Digest(out, sizeof(out));
            }
            break;
        case    CF_DIGEST("SHAKE256"):
            {
                uint8_t out[32];
                br_shake_context ctx;
                const auto parts = util::ToParts(ds, op.cleartext);

                /* noret */ br_shake_init(&ctx, 256);
                for (const auto& part : parts) {
                    /* noret */ br_shake_inject(&ctx, part.first, part.second);
                }
                /* noret */ br_shake_flip(&ctx);
                /* noret */ br_shake_produce(&ctx, out, 32);

                ret = component::Digest(out, sizeof(out));
            }
            break;
    }

    return ret;
}

std::optional<component::MAC> BearSSL::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    br_hmac_context ctx;
    br_hmac_key_context kctx;
    uint8_t out[64];
    const auto parts = util::ToParts(ds, op.cleartext);
    const br_hash_class* hash_class;

    /* Initialize */
    {
        CF_CHECK_NE(hash_class = BearSSL_detail::To_br_hash_class(op.digestType), nullptr);

        /* noret */ br_hmac_key_init(&kctx, hash_class, op.cipher.key.GetPtr(), op.cipher.key.GetSize());
        /* noret */ br_hmac_init(&ctx, &kctx, 0);
    }

    /* Process */
    for (const auto& part : parts) {
        br_hmac_update(&ctx, part.first, part.second);
    }

    {
        const auto size = br_hmac_out(&ctx, out);

        ret = component::MAC(out, size);
    }

end:
    return ret;
}

std::optional<component::Ciphertext> BearSSL::OpSymmetricEncrypt(operation::SymmetricEncrypt& op) {
    std::optional<component::Ciphertext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    uint8_t* tag = nullptr;

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("AES_128_GCM"):
        case    CF_CIPHER("AES_192_GCM"):
        case    CF_CIPHER("AES_256_GCM"):
            {
                br_aes_ct_ctr_keys bc;
                br_gcm_context gc;
                tag = util::malloc(16);
                auto in = op.cleartext.Get();
                auto parts = util::ToParts(ds, in);

                switch ( op.cipher.cipherType.Get() ) {
                    case    CF_CIPHER("AES_128_GCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                        break;
                    case    CF_CIPHER("AES_192_GCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                        break;
                    case    CF_CIPHER("AES_256_GCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                        break;
                }

                if ( op.tagSize != std::nullopt ) {
                    CF_CHECK_EQ(*op.tagSize, 16);
                }

                CF_CHECK_GT(op.cipher.iv.GetSize(), 0);

                /* noret */ br_aes_ct_ctr_init(&bc, op.cipher.key.GetPtr(), op.cipher.key.GetSize());
                /* noret */ br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);

                /* noret */ br_gcm_reset(&gc, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
                if ( op.aad != std::nullopt ) {
                    const auto aadParts = util::ToParts(ds, *op.aad);
                    /* "Additional data may be provided in several chunks of arbitrary length" */
                    for (auto& part : aadParts) {
                        /* noret */ br_gcm_aad_inject(&gc, part.first, part.second);
                    }
                }
                /* noret */ br_gcm_flip(&gc);

                for (auto& part : parts) {
                    /* "Data may be provided in several chunks of arbitrary length" */
                    /* noret */ br_gcm_run(&gc, 1, (void*)part.first, part.second);
                }

                if ( op.tagSize != std::nullopt ) {
                    /* noret */ br_gcm_get_tag(&gc, tag);
                    ret = component::Ciphertext(Buffer(in), Buffer(tag, 16));
                } else {
                    ret = component::Ciphertext(Buffer(in));
                }
            }
            break;
        case    CF_CIPHER("AES_128_CCM"):
        case    CF_CIPHER("AES_192_CCM"):
        case    CF_CIPHER("AES_256_CCM"):
            {
                br_aes_gen_ctrcbc_keys bc;
                br_ccm_context ec;
                auto in = op.cleartext.Get();
                auto parts = util::ToParts(ds, in);
                const auto vt = BearSSL_detail::Get_br_block_ctrcbc_class(ds);
                CF_CHECK_NE(vt, nullptr);

                switch ( op.cipher.cipherType.Get() ) {
                    case    CF_CIPHER("AES_128_CCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                        break;
                    case    CF_CIPHER("AES_192_CCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                        break;
                    case    CF_CIPHER("AES_256_CCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                        break;
                }

                if ( op.tagSize != std::nullopt ) {
                    tag = util::malloc(*op.tagSize);
                }

                CF_CHECK_GT(op.cipher.iv.GetSize(), 0);

                /* noret */ vt->init(&bc.vtable, op.cipher.key.GetPtr(), op.cipher.key.GetSize());
                /* noret */ br_ccm_init(&ec, &bc.vtable);

                CF_CHECK_NE(br_ccm_reset(&ec,
                            op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(),
                            op.aad == std::nullopt ? 0 : op.aad->GetSize(),
                            op.cleartext.GetSize(),
                            op.tagSize == std::nullopt ? 0 : *op.tagSize), 0);

                if ( op.aad != std::nullopt ) {
                    const auto aadParts = util::ToParts(ds, *op.aad);
                    /* "Additional data may be provided in several chunks of arbitrary length" */
                    for (auto& part : aadParts) {
                        /* noret */ br_ccm_aad_inject(&ec, part.first, part.second);
                    }
                }
                /* noret */ br_ccm_flip(&ec);

                for (auto& part : parts) {
                    /* "Data may be provided in several chunks of arbitrary length" */
                    /* noret */ br_ccm_run(&ec, 1, (void*)part.first, part.second);
                }

                if ( op.tagSize != std::nullopt ) {
                    /* noret */ br_ccm_get_tag(&ec, tag);
                    ret = component::Ciphertext(Buffer(in), Buffer(tag, *op.tagSize));
                } else {
                    ret = component::Ciphertext(Buffer(in));
                }
            }
            break;
        case    CF_CIPHER("CHACHA20"):
            {
                CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);

                auto in = op.cleartext.Get();

                auto cc20 = BearSSL_detail::Get_br_chacha20_run(ds);
                cc20(op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), 0, in.data(), in.size());
                ret = component::Ciphertext(Buffer(in));
            }
            break;
        case    CF_CIPHER("CHACHA20_POLY1305"):
            {
                CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);

                if ( op.tagSize != std::nullopt ) {
                    CF_CHECK_EQ(*op.tagSize, 16);
                }

                uint8_t tag[16];
                auto in = op.cleartext.Get();
                auto cc20 = BearSSL_detail::Get_br_chacha20_run(ds);

                br_poly1305_ctmul_run(
                        op.cipher.key.GetPtr(),
                        op.cipher.iv.GetPtr(),
                        in.data(),
                        in.size(),
                        op.aad == std::nullopt ? nullptr : op.aad->GetPtr(),
                        op.aad == std::nullopt ? 0 : op.aad->GetSize(),
                        tag,
                        cc20,
                        1);

                if ( op.tagSize != std::nullopt ) {
                    ret = component::Ciphertext(Buffer(in), Buffer(tag, 16));
                } else {
                    ret = component::Ciphertext(Buffer(in));
                }
            }
            break;
    }

end:
    util::free(tag);

    return ret;
}

std::optional<component::Cleartext> BearSSL::OpSymmetricDecrypt(operation::SymmetricDecrypt& op) {
    std::optional<component::Cleartext> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    switch ( op.cipher.cipherType.Get() ) {
        case    CF_CIPHER("AES_128_GCM"):
        case    CF_CIPHER("AES_192_GCM"):
        case    CF_CIPHER("AES_256_GCM"):
            {
                br_aes_ct_ctr_keys bc;
                br_gcm_context gc;
                auto in = op.ciphertext.Get();
                auto parts = util::ToParts(ds, in);

                switch ( op.cipher.cipherType.Get() ) {
                    case    CF_CIPHER("AES_128_GCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                        break;
                    case    CF_CIPHER("AES_192_GCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                        break;
                    case    CF_CIPHER("AES_256_GCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                        break;
                }

                if ( op.tag != std::nullopt ) {
                    CF_CHECK_EQ(op.tag->GetSize(), 16);
                }

                CF_CHECK_GT(op.cipher.iv.GetSize(), 0);

                /* noret */ br_aes_ct_ctr_init(&bc, op.cipher.key.GetPtr(), op.cipher.key.GetSize());
                /* noret */ br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul32);

                /* noret */ br_gcm_reset(&gc, op.cipher.iv.GetPtr(), op.cipher.iv.GetSize());
                if ( op.aad != std::nullopt ) {
                    const auto aadParts = util::ToParts(ds, *op.aad);
                    /* "Additional data may be provided in several chunks of arbitrary length" */
                    for (auto& part : aadParts) {
                        /* noret */ br_gcm_aad_inject(&gc, part.first, part.second);
                    }
                }
                /* noret */ br_gcm_flip(&gc);

                for (auto& part : parts) {
                    /* "Data may be provided in several chunks of arbitrary length" */
                    /* noret */ br_gcm_run(&gc, 0, (void*)part.first, part.second);
                }

                if ( op.tag != std::nullopt ) {
                    CF_CHECK_EQ(br_gcm_check_tag(&gc, op.tag->GetPtr()), 1);
                }

                ret = component::Cleartext(Buffer(in));
            }
            break;
        case    CF_CIPHER("AES_128_CCM"):
        case    CF_CIPHER("AES_192_CCM"):
        case    CF_CIPHER("AES_256_CCM"):
            {
                br_aes_gen_ctrcbc_keys bc;
                br_ccm_context ec;
                auto in = op.ciphertext.Get();
                auto parts = util::ToParts(ds, in);
                const auto vt = BearSSL_detail::Get_br_block_ctrcbc_class(ds);
                CF_CHECK_NE(vt, nullptr);

                switch ( op.cipher.cipherType.Get() ) {
                    case    CF_CIPHER("AES_128_CCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 16);
                        break;
                    case    CF_CIPHER("AES_192_CCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 24);
                        break;
                    case    CF_CIPHER("AES_256_CCM"):
                        CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                        break;
                }

                CF_CHECK_GT(op.cipher.iv.GetSize(), 0);

                /* noret */ vt->init(&bc.vtable, op.cipher.key.GetPtr(), op.cipher.key.GetSize());
                /* noret */ br_ccm_init(&ec, &bc.vtable);

                CF_CHECK_NE(br_ccm_reset(&ec,
                            op.cipher.iv.GetPtr(), op.cipher.iv.GetSize(),
                            op.aad == std::nullopt ? 0 : op.aad->GetSize(),
                            op.ciphertext.GetSize(),
                            op.tag == std::nullopt ? 0 : op.tag->GetSize()), 0);

                if ( op.aad != std::nullopt ) {
                    const auto aadParts = util::ToParts(ds, *op.aad);
                    /* "Additional data may be provided in several chunks of arbitrary length" */
                    for (auto& part : aadParts) {
                        /* noret */ br_ccm_aad_inject(&ec, part.first, part.second);
                    }
                }
                /* noret */ br_ccm_flip(&ec);

                for (auto& part : parts) {
                    /* "Data may be provided in several chunks of arbitrary length" */
                    /* noret */ br_ccm_run(&ec, 0, (void*)part.first, part.second);
                }

                if ( op.tag != std::nullopt ) {
                    CF_CHECK_EQ(br_ccm_check_tag(&ec, op.tag->GetPtr()), 1);
                }

                ret = component::Cleartext(Buffer(in));
            }
            break;
        case    CF_CIPHER("CHACHA20"):
            {
                CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);

                auto cc20 = BearSSL_detail::Get_br_chacha20_run(ds);
                auto in = op.ciphertext.Get();

                cc20(op.cipher.key.GetPtr(), op.cipher.iv.GetPtr(), 0, in.data(), in.size());
                ret = component::Cleartext(Buffer(in));
            }
            break;
        case    CF_CIPHER("CHACHA20_POLY1305"):
            {
                CF_CHECK_EQ(op.cipher.key.GetSize(), 32);
                CF_CHECK_EQ(op.cipher.iv.GetSize(), 12);

                if ( op.tag != std::nullopt ) {
                    CF_CHECK_EQ(op.tag->GetSize(), 16);
                }

                uint8_t tag[16];
                auto in = op.ciphertext.Get();
                auto cc20 = BearSSL_detail::Get_br_chacha20_run(ds);

                br_poly1305_ctmul_run(
                        op.cipher.key.GetPtr(),
                        op.cipher.iv.GetPtr(),
                        in.data(),
                        in.size(),
                        op.aad == std::nullopt ? nullptr : op.aad->GetPtr(),
                        op.aad == std::nullopt ? 0 : op.aad->GetSize(),
                        tag,
                        cc20,
                        0);

                if ( op.tag != std::nullopt ) {
                    CF_CHECK_EQ(memcmp(op.tag->GetPtr(), tag, 16), 0);
                }

                ret = component::Cleartext(Buffer(in));
            }
            break;
    }

end:
    return ret;
}

std::optional<component::Key> BearSSL::OpKDF_HKDF(operation::KDF_HKDF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    br_hkdf_context ctx;
    const br_hash_class* hash_class;
    uint8_t* out = util::malloc(op.keySize);

    /* Initialize */
    {
        const auto digestSize = repository::DigestSize(op.digestType.Get());
        CF_CHECK_NE(digestSize, std::nullopt);
        CF_CHECK_LTE(op.keySize, 255 * *digestSize);

        CF_CHECK_NE(hash_class = BearSSL_detail::To_br_hash_class(op.digestType), nullptr);
        /* noret */ br_hkdf_init(&ctx, hash_class, op.salt.GetPtr(), op.salt.GetSize());
    }

    /* Process */
    {
        const auto parts = util::ToParts(ds, op.password);

        /* "This function may be called several times" https://bearssl.org/apidoc/bearssl__kdf_8h.html */
        for (const auto& part : parts) {
            /* noret */ br_hkdf_inject(&ctx, part.first, part.second);
        }
    }

    /* noret */ br_hkdf_flip(&ctx);

    /* Finalize */
    {
        br_hkdf_produce(&ctx, op.info.GetPtr(), op.info.GetSize(), out, op.keySize);

        ret = component::Key(out, op.keySize);
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::Key> BearSSL::OpKDF_TLS1_PRF(operation::KDF_TLS1_PRF& op) {
    std::optional<component::Key> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const auto parts = util::ToParts(ds, op.seed);
    br_tls_prf_seed_chunk* seed_chunks = (br_tls_prf_seed_chunk*)util::malloc(parts.size() * sizeof(br_tls_prf_seed_chunk));
    uint8_t* out = util::malloc(op.keySize);

    CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("MD5_SHA1"));

    {
        size_t i = 0;
        for (const auto& part : parts) {
            seed_chunks[i].data = part.first;
            seed_chunks[i].len = part.second;
            i++;
        }
    }

    /* noret */ br_tls10_prf(
            out,
            op.keySize,
            op.secret.GetPtr(), op.secret.GetSize(),
            "",
            parts.size(),
            seed_chunks);

    ret = component::Key(out, op.keySize);

end:
    util::free(out);
    util::free(seed_chunks);

    return ret;
}

std::optional<component::ECC_KeyPair> BearSSL::OpECC_GenerateKeyPair(operation::ECC_GenerateKeyPair& op) {
    std::optional<component::ECC_KeyPair> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    br_ec_private_key sk;
    br_ec_public_key pk;
    uint8_t priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    uint8_t pub[BR_EC_KBUF_PUB_MAX_SIZE];
    size_t privSize, pubSize;
    int curve;
    const auto ec_impl = BearSSL_detail::Get_br_ec_impl(ds, op.curveType);

    CF_CHECK_NE(curve = BearSSL_detail::toCurveID(op.curveType), -1);

    CF_CHECK_NE(privSize = br_ec_keygen(&BearSSL_detail::rng.vtable, ec_impl, &sk, priv, curve), 0);
    CF_CHECK_NE(pubSize = br_ec_compute_pub(ec_impl, &pk, pub, &sk), 0);

    if ( op.curveType.Is(CF_ECC_CURVE("x25519")) ) {
        std::reverse(priv, priv + privSize);
    }

    ret = { BearSSL_detail::toString(priv, privSize), BearSSL_detail::EncodePubkey(op.curveType, pub, pubSize) };
end:
    return ret;
}

std::optional<component::ECC_PublicKey> BearSSL::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    br_ec_private_key sk;
    br_ec_public_key pk;
    uint8_t priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    uint8_t pub[BR_EC_KBUF_PUB_MAX_SIZE];
    size_t privSize;
    size_t pubSize;
    const auto ec_impl = BearSSL_detail::Get_br_ec_impl(ds, op.curveType);

    CF_CHECK_NE(sk.curve = BearSSL_detail::toCurveID(op.curveType), -1);
    CF_CHECK_EQ(BearSSL_detail::IsValidPrivateKey(op.priv, op.curveType), true);
    {
        bool reverse;

        if ( op.curveType.Is(CF_ECC_CURVE("x25519")) ) {
            privSize = 32;
            reverse = true;
        } else {
            reverse = false;
            privSize = sizeof(priv);
        }
        CF_CHECK_EQ(BearSSL_detail::EncodeBignum(op.priv.ToTrimmedString(), priv, privSize, reverse), true);
    }

    sk.x = priv;
    sk.xlen = privSize;

    memset(&pk, 0, sizeof(pk));
    CF_CHECK_NE(pubSize = br_ec_compute_pub(ec_impl, &pk, pub, &sk), 0);
    ret = BearSSL_detail::EncodePubkey(op.curveType, pub, pubSize);

end:
    return ret;
}

std::optional<bool> BearSSL::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    size_t generator_len;
    size_t signature_len;
    switch ( op.curveType.Get() ) {
        case CF_ECC_CURVE("secp256r1"):
            generator_len = 65;
            signature_len = 64;
            break;
        case CF_ECC_CURVE("secp384r1"):
            generator_len = 97;
            signature_len = 96;
            break;
        case CF_ECC_CURVE("secp521r1"):
            generator_len = 133;
            signature_len = 132;
            break;
        default:
            return std::nullopt;
    }

    size_t pubkeyHalfSize = (generator_len - 1) / 2;
    size_t signatureHalfSize = signature_len / 2;
    uint8_t* signature = util::malloc(signature_len);
    uint8_t* pub = util::malloc(generator_len);
    br_ec_public_key pk;
    const auto ec_impl = BearSSL_detail::Get_br_ec_impl(ds, op.curveType);
    auto verify = BearSSL_detail::Get_br_ecdsa_vrfy(ds);
    const br_hash_class* hash_class;
    uint8_t _hash[64];
    const uint8_t* hash;
    size_t hash_size = 0;

    if ( op.digestType.Get() == CF_DIGEST("NULL") ) {
        hash = op.cleartext.GetPtr();
        hash_size = op.cleartext.GetSize();
    } else {
        br_hash_compat_context hc;

        CF_CHECK_NE(hash_class = BearSSL_detail::To_br_hash_class(op.digestType), nullptr);

        hash_class->init(&hc.vtable);
        hash_class->update(&hc.vtable, op.cleartext.GetPtr(), op.cleartext.GetSize());
        hash_class->out(&hc.vtable, _hash);
        hash = _hash;
        hash_size = (hash_class->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
    }
    CF_CHECK_NE(pk.curve = BearSSL_detail::toCurveID(op.curveType), -1);

    CF_CHECK_EQ(BearSSL_detail::EncodeBignum(op.signature.signature.first.ToTrimmedString(), signature, signatureHalfSize), true);
    CF_CHECK_EQ(BearSSL_detail::EncodeBignum(op.signature.signature.second.ToTrimmedString(), signature + signatureHalfSize, signatureHalfSize), true);

    pub[0] = 0x04;
    CF_CHECK_EQ(BearSSL_detail::EncodeBignum(op.signature.pub.first.ToTrimmedString(), pub + 1, pubkeyHalfSize), true);
    CF_CHECK_EQ(BearSSL_detail::EncodeBignum(op.signature.pub.second.ToTrimmedString(), pub + 1 + pubkeyHalfSize, pubkeyHalfSize), true);

    pk.q = pub;
    pk.qlen = generator_len;

    ret = verify(
            ec_impl,
            hash,
            hash_size,
            &pk,
            signature,
            signature_len);
end:

    util::free(signature);
    util::free(pub);

    return ret;
}

std::optional<component::ECDSA_Signature> BearSSL::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    size_t signature_len;
    switch ( op.curveType.Get() ) {
        case CF_ECC_CURVE("secp256r1"):
            signature_len = 64;
            break;
        case CF_ECC_CURVE("secp384r1"):
            signature_len = 96;
            break;
        case CF_ECC_CURVE("secp521r1"):
            signature_len = 132;
            break;
        default:
            return std::nullopt;
    }

    br_ec_private_key sk;
    br_ec_public_key pk;
    uint8_t priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    uint8_t pub[BR_EC_KBUF_PUB_MAX_SIZE];
    size_t pubSize;
    uint8_t* signature = util::malloc(signature_len);
    size_t sigSize;
    uint8_t hash[64];
    br_hash_compat_context hc;
    const br_hash_class* hash_class;
    const auto ec_impl = BearSSL_detail::Get_br_ec_impl(ds, op.curveType);
    auto sign = BearSSL_detail::Get_br_ecdsa_sign(ds);

    CF_CHECK_EQ(op.UseRFC6979Nonce(), true);
    CF_CHECK_NE(hash_class = BearSSL_detail::To_br_hash_class(op.digestType), nullptr);

    CF_CHECK_NE(sk.curve = BearSSL_detail::toCurveID(op.curveType), -1);
    CF_CHECK_EQ(BearSSL_detail::IsValidPrivateKey(op.priv, op.curveType), true);
    CF_CHECK_EQ(BearSSL_detail::EncodeBignum(op.priv.ToTrimmedString(), priv, sizeof(priv)), true);

    hash_class->init(&hc.vtable);
    hash_class->update(&hc.vtable, op.cleartext.GetPtr(), op.cleartext.GetSize());
    hash_class->out(&hc.vtable, hash);

    sk.x = priv;
    sk.xlen = sizeof(priv);

    memset(&pk, 0, sizeof(pk));
    CF_CHECK_NE(pubSize = br_ec_compute_pub(ec_impl, &pk, pub, &sk), 0);

    CF_CHECK_NE(sigSize = sign(ec_impl, hash_class, hash, &sk, signature), 0);

    if ( sigSize % 2 != 0 ) {
        abort();
    }

    /* Disabled because signature S needs to be corrected for compatibility with Botan/Trezor */
    CF_CHECK_NE(op.curveType.Get(), CF_ECC_CURVE("secp256r1"));

    ret = {
            {BearSSL_detail::toString(signature, sigSize / 2), BearSSL_detail::toString(signature + (sigSize/2), sigSize / 2) },
            BearSSL_detail::EncodePubkey(op.curveType, pub, pubSize)
    };

end:
    util::free(signature);
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
