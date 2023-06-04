#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <boost/lexical_cast.hpp>
#include <iostream>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

extern "C" {
    #include <libsig.h>
    #include <hash/hmac.h>
}

namespace cryptofuzz {
namespace module {
namespace libecc_detail {
    Datasource* global_ds = nullptr;
    FILE* fp_dev_urandom = nullptr;
    const ec_sig_mapping *sm_ecdsa, *sm_ecgdsa, *sm_ecrdsa;

    std::map<uint64_t, const ec_str_params*> curveLUT;

    static void AddCurve(const uint64_t curveID, const std::string& curveName) {
        int ret;
        const ec_str_params *curve_params;

        ret = ec_get_curve_params_by_name((const u8*)curveName.c_str(), curveName.size() + 1, &curve_params);

        CF_ASSERT((!ret) && (curve_params != nullptr), "Cannot initialize curve");

        curveLUT[curveID] = curve_params;
    }

    static const ec_str_params* GetCurve(const component::CurveType& curveType) {
        if ( curveLUT.find(curveType.Get()) == curveLUT.end() ) {
            return nullptr;
        }

        return curveLUT.at(curveType.Get());
    }
    std::optional<component::BignumPair> To_Component_BignumPair(const ec_pub_key& pub) {
        std::optional<component::BignumPair> ret = std::nullopt;

        uint8_t* out = nullptr;
        const size_t outSize = EC_PUB_KEY_EXPORT_SIZE(&pub);
        CF_ASSERT((outSize % 2) == 0, "Public key byte size is not even");
        CF_ASSERT((outSize % 3) == 0, "Public key byte size is not multiple of 3");
        out = util::malloc(outSize);
        CF_CHECK_EQ(ec_pub_key_export_to_buf(&pub, out, outSize), 0);
        {
            const size_t pointSize = outSize / 3;
            const auto X = util::BinToDec(out, pointSize);
            const auto Y = util::BinToDec(out + pointSize, pointSize);

            ret = {X, Y};
        }

end:
        util::free(out);

        return ret;
    }

    bool To_nn_t(const component::Bignum& bn, nn_t nn) {
        const auto data = util::DecToBin(bn.ToTrimmedString());
        if ( data == std::nullopt ) {
            return false;
        }
        if ( (8 * data->size()) > NN_USABLE_MAX_BIT_LEN ) {
            return false;
        }

        CF_ASSERT(!nn_init_from_buf(nn, data->data(), data->size()), "nn_init_from_buf error " __FILE__ ":" TOSTRING(__LINE__));

        return true;
    }

    component::Bignum To_Component_Bignum(const nn_src_t nn, const bool negative = false) {
        std::vector<uint8_t> data(nn->wlen * WORD_BYTES);

        if ( data.size() == 0 ) {
            data.resize(1);
        }

        CF_ASSERT(!nn_export_to_buf(data.data(), data.size(), nn), "nn_export_to_buf error " __FILE__ ":" TOSTRING(__LINE__));

        const auto s = util::BinToDec(data.data(), data.size());

        if ( negative && s != "0" ) {
            return std::string("-") + s;
        } else {
            return s;
        }
    }

    std::optional<uint16_t> To_uint16_t(const component::Bignum& bn) {
        const auto data = util::DecToBin(bn.ToTrimmedString(), sizeof(uint16_t));
        if ( data == std::nullopt ) {
            return std::nullopt;
        }

        return (((size_t)data->data()[0]) << 8) + data->data()[1];
    }

    const hash_mapping* To_hash_mapping(const uint64_t digestType) {
        const hash_mapping *hm;
        switch ( digestType ) {
            case    CF_DIGEST("SHA224"):
                CF_ASSERT(!get_hash_by_type(SHA224, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA256"):
                CF_ASSERT(!get_hash_by_type(SHA256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA384"):
                CF_ASSERT(!get_hash_by_type(SHA384, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA512"):
                CF_ASSERT(!get_hash_by_type(SHA512, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA512-224"):
                CF_ASSERT(!get_hash_by_type(SHA512_224, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA512-256"):
                CF_ASSERT(!get_hash_by_type(SHA512_256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-224"):
                CF_ASSERT(!get_hash_by_type(SHA3_224, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-256"):
                CF_ASSERT(!get_hash_by_type(SHA3_256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-384"):
                CF_ASSERT(!get_hash_by_type(SHA3_384, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHA3-512"):
                CF_ASSERT(!get_hash_by_type(SHA3_512, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SM3"):
                CF_ASSERT(!get_hash_by_type(SM3, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("SHAKE256_114"):
                CF_ASSERT(!get_hash_by_type(SHAKE256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("STREEBOG-256"):
                CF_ASSERT(!get_hash_by_type(STREEBOG256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("STREEBOG-512"):
                CF_ASSERT(!get_hash_by_type(STREEBOG512, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("RIPEMD160"):
                CF_ASSERT(!get_hash_by_type(RIPEMD160, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("BASH224"):
                CF_ASSERT(!get_hash_by_type(BASH224, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("BASH256"):
                CF_ASSERT(!get_hash_by_type(BASH256, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("BASH384"):
                CF_ASSERT(!get_hash_by_type(BASH384, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            case    CF_DIGEST("BASH512"):
                CF_ASSERT(!get_hash_by_type(BASH512, &hm) && (hm != nullptr), "get_hash_by_type error " __FILE__ ":" TOSTRING(__LINE__));
                return hm;
            default:
                return nullptr;
        }
    }

    std::optional<hash_alg_type> To_hash_alg_type(const uint64_t digestType) {
        switch ( digestType ) {
            case    CF_DIGEST("SHA224"):
                return SHA224;
            case    CF_DIGEST("SHA256"):
                return SHA256;
            case    CF_DIGEST("SHA384"):
                return SHA384;
            case    CF_DIGEST("SHA512"):
                return SHA512;
            case    CF_DIGEST("SHA512-224"):
                return SHA512_224;
            case    CF_DIGEST("SHA512-256"):
                return SHA512_256;
            case    CF_DIGEST("SHA3-224"):
                return SHA3_224;
            case    CF_DIGEST("SHA3-256"):
                return SHA3_256;
            case    CF_DIGEST("SHA3-384"):
                return SHA3_384;
            case    CF_DIGEST("SHA3-512"):
                return SHA3_512;
            case    CF_DIGEST("SM3"):
                return SM3;
            case    CF_DIGEST("SHAKE256_114"):
                return SHAKE256;
            case    CF_DIGEST("STREEBOG-256"):
                return STREEBOG256;
            case    CF_DIGEST("STREEBOG-512"):
                return STREEBOG512;
            case    CF_DIGEST("RIPEMD160"):
                return RIPEMD160;
            case    CF_DIGEST("BASH224"):
                return BASH224;
            case    CF_DIGEST("BASH256"):
                return BASH256;
            case    CF_DIGEST("BASH384"):
                return BASH384;
            case    CF_DIGEST("BASH512"):
                return BASH512;
            default:
                return std::nullopt;
        }
    }
}
}
}

extern "C" int get_random(unsigned char *buf, u16 len) {
    CF_ASSERT(cryptofuzz::module::libecc_detail::global_ds != nullptr, "Global datasource is NULL");

    if ( len == 0 ) {
        return 0;
    }

    try {
        const auto data = cryptofuzz::module::libecc_detail::global_ds->GetData(0, len, len);
        memcpy(buf, data.data(), len);
        return 0;
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    CF_ASSERT(fread(buf, len, 1, cryptofuzz::module::libecc_detail::fp_dev_urandom) == 1, "Reading from /dev/urandom failed");

    return 0;
}

namespace cryptofuzz {
namespace module {

libecc::libecc(void) :
    Module("libecc") {
    CF_ASSERT((libecc_detail::fp_dev_urandom = fopen("/dev/urandom", "rb")) != NULL, "Failed to open /dev/urandom");
    CF_ASSERT((!get_sig_by_name("ECDSA", &(libecc_detail::sm_ecdsa))) && ((libecc_detail::sm_ecdsa) != nullptr), "Cannot initialize ECDSA");
    CF_ASSERT((!get_sig_by_name("ECGDSA", &(libecc_detail::sm_ecgdsa))) && ((libecc_detail::sm_ecgdsa) != nullptr), "Cannot initialize ECGDSA");
    CF_ASSERT((!get_sig_by_name("ECRDSA", &(libecc_detail::sm_ecrdsa))) && ((libecc_detail::sm_ecrdsa) != nullptr), "Cannot initialize ECRDSA");

    /* Load curves */
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool192r1"), "BRAINPOOLP192R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool192t1"), "BRAINPOOLP192T1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool224r1"), "BRAINPOOLP224R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool224t1"), "BRAINPOOLP224T1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool256r1"), "BRAINPOOLP256R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool256t1"), "BRAINPOOLP256T1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool320r1"), "BRAINPOOLP320R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool320t1"), "BRAINPOOLP320T1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool384r1"), "BRAINPOOLP384R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool384t1"), "BRAINPOOLP384T1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool512r1"), "BRAINPOOLP512R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool512t1"), "BRAINPOOLP512T1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp192r1"), "SECP192R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp192k1"), "SECP192K1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp224r1"), "SECP224R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp224k1"), "SECP224K1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp256r1"), "SECP256R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp256k1"), "SECP256K1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp384r1"), "SECP384R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp521r1"), "SECP521R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("frp256v1"), "FRP256V1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp256k1"), "SECP256K1");
    libecc_detail::AddCurve(CF_ECC_CURVE("sm2p256v1"), "SM2P256V1");
    libecc_detail::AddCurve(CF_ECC_CURVE("gost_256A"), "GOST_R3410_2012_256_PARAMSETA");
    libecc_detail::AddCurve(CF_ECC_CURVE("gost_512A"), "GOST_R3410_2012_512_PARAMSETA");
    libecc_detail::AddCurve(CF_ECC_CURVE("gostr3410_2001_cryptopro_a"), "GOST_R3410_2001_CRYPTOPRO_A_PARAMSET");
    libecc_detail::AddCurve(CF_ECC_CURVE("gostr3410_2001_cryptopro_b"), "GOST_R3410_2001_CRYPTOPRO_B_PARAMSET");
    libecc_detail::AddCurve(CF_ECC_CURVE("gostr3410_2001_cryptopro_c"), "GOST_R3410_2001_CRYPTOPRO_C_PARAMSET");
    libecc_detail::AddCurve(CF_ECC_CURVE("gostr3410_2001_cryptopro_xcha"), "GOST_R3410_2001_CRYPTOPRO_XCHA_PARAMSET");
    libecc_detail::AddCurve(CF_ECC_CURVE("gostr3410_2001_cryptopro_xchb"), "GOST_R3410_2001_CRYPTOPRO_XCHB_PARAMSET");
    libecc_detail::AddCurve(CF_ECC_CURVE("gostr3410_2001_test"), "GOST_R3410_2001_TESTPARAMSET");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_256_a"), "GOST_R3410_2012_256_PARAMSETA");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_256_b"), "GOST_R3410_2012_256_PARAMSETB");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_256_c"), "GOST_R3410_2012_256_PARAMSETC");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_256_d"), "GOST_R3410_2012_256_PARAMSETD");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_512_a"), "GOST_R3410_2012_512_PARAMSETA");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_512_b"), "GOST_R3410_2012_512_PARAMSETB");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_512_c"), "GOST_R3410_2012_512_PARAMSETC");
    libecc_detail::AddCurve(CF_ECC_CURVE("tc26_gost_3410_12_512_test"), "GOST_R3410_2012_512_PARAMSETTEST");

    /* NOTE: Ed25519 and Ed448 are mapped to WEI25519 and WEI448 by libecc
     * through isogenies.
     */
    libecc_detail::AddCurve(CF_ECC_CURVE("ed25519"), "WEI25519");
    libecc_detail::AddCurve(CF_ECC_CURVE("ed448"), "WEI448");
    /* NOTE: x25519 and x448 are mapped to WEI25519 and WEI448 by libecc
     * through isogenies.
     */
    libecc_detail::AddCurve(CF_ECC_CURVE("x25519"), "WEI25519");
    libecc_detail::AddCurve(CF_ECC_CURVE("x448"), "WEI448");

    /* TODO */
#if 0
    "GOST256"
    "GOST512"
#endif
}

std::optional<component::Digest> libecc::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    hash_context ctx;
    uint8_t* out = nullptr;
    const hash_mapping* hash;

    CF_CHECK_NE(hash = libecc_detail::To_hash_mapping(op.digestType.Get()), nullptr);

    /* Initialize */
    CF_ASSERT(!(hash->hfunc_init(&ctx)), "hfunc_init error " __FILE__ ":" TOSTRING(__LINE__));

    {
    /* Process */
        const auto parts = util::ToParts(ds, op.cleartext);
        for (const auto& part : parts) {
            if ( part.first == nullptr ) {
                continue;
            }
            CF_ASSERT(!(hash->hfunc_update(&ctx, part.first, part.second)), "hfunc_update error " __FILE__ ":" TOSTRING(__LINE__));
        }
    }

    /* Finalize */
    {
        out = util::malloc(hash->digest_size);
        CF_ASSERT(!(hash->hfunc_finalize(&ctx, out)), "hfunc_finalize error " __FILE__ ":" TOSTRING(__LINE__));

        ret = component::Digest(out, hash->digest_size);
    }

end:
    util::free(out);

    return ret;
}

std::optional<component::MAC> libecc::OpHMAC(operation::HMAC& op) {
    std::optional<component::MAC> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    bool oneShot = false;
    uint8_t outlen = 0;
    uint8_t* out = nullptr;
    std::optional<hash_alg_type> hash;

    CF_CHECK_NE(hash = libecc_detail::To_hash_alg_type(op.digestType.Get()), std::nullopt);

    try {
        outlen = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    try {
        oneShot = ds.Get<bool>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    out = util::malloc(outlen);

    if ( oneShot == true ) {
        CF_CHECK_EQ(hmac(
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    *hash,
                    op.cleartext.GetPtr(),
                    op.cleartext.GetSize(),
                    out, &outlen
                    ), 0);

        ret = component::Digest(out, outlen);
    } else {
        hmac_context ctx;

        /* Initialize */
        CF_CHECK_EQ(hmac_init(
                    &ctx,
                    op.cipher.key.GetPtr(),
                    op.cipher.key.GetSize(),
                    *hash), 0);

        {
            const auto parts = util::ToParts(ds, op.cleartext);

            for (const auto& part : parts) {
                if ( part.first == nullptr ) {
                    continue;
                }

                CF_CHECK_EQ(hmac_update(&ctx, part.first, part.second), 0);
            }
        }

        /* Finalize */
        {
            CF_CHECK_EQ(hmac_finalize(&ctx, out, &outlen), 0);
            ret = component::Digest(out, outlen);
        }
    }

end:
    util::free(out);

    return ret;
}

namespace libecc_detail {
std::optional<bool> OpECC_ValidatePubkey(operation::ECC_ValidatePubkey& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
    libecc_detail::global_ds = &ds;

    const ec_str_params* curve_params;
    ec_params params;
    ec_pub_key pub_key;

    /* Load curve.
     * NOTE: this will be WEI25519 or WEI448 (libecc uses isogenies for ed25519, ed448, x25519 and x448)
     * for EdDSA and X25519/X448
     */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    /* Skip the ed25519, ed448, x25519 and x448 special cases */
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) || op.curveType.Is(CF_ECC_CURVE("ed448")) ) {
        /* XXX: see if OpECC_ValidatePubkey is called on x coordinates only, or points on Edwards curves? */
        goto end;
    }
    if ( op.curveType.Is(CF_ECC_CURVE("x25519")) || op.curveType.Is(CF_ECC_CURVE("x448")) ) {
        /* XXX: see if OpECC_ValidatePubkey is called on x coordinates only encoded strings? */
        goto end;
    }

    {
        /* Generic case, extract X and Y, and check the point on the curve */
        const auto ax_bin = util::DecToBin(op.pub.first.ToTrimmedString());
        const auto ay_bin = util::DecToBin(op.pub.second.ToTrimmedString());
        fp x, y;
        u8 *pub_buff = NULL;
        u16 coord_len = (u16)BYTECEIL(params.ec_fp.p_bitlen);

        if(fp_init_from_buf(&x, &(params.ec_fp), ax_bin->data(), ax_bin->size())){
            ret = false;
            goto end1;
        }

        if(fp_init_from_buf(&y, &(params.ec_fp), ay_bin->data(), ay_bin->size())){
            ret = false;
            goto end1;
        }

        /* Allocate a buffer for our stringified public key */
        CF_ASSERT((coord_len % 2) == 0, "Coordinates size is not multiple of 2");
        pub_buff = util::malloc(coord_len);

        if(fp_export_to_buf(&pub_buff[0], coord_len / 2, &x)){
            ret = false;
            goto end1;
        }
        if(fp_export_to_buf(&pub_buff[coord_len / 2], coord_len / 2, &y)){
            ret = false;
            goto end1;
        }

        /* Try to import the public key on the curve (and perform the underlying checks).
         * This will return an error if the public key is rejected!
         * NOTE: we choose randomly ECDSA as the signature algorithm type as all the signatures expect
	 * a point on their curve anyways!
         */
        if(ec_pub_key_import_from_aff_buf(&pub_key, &params, &pub_buff[0], coord_len, ECDSA)){
            ret = false;
            goto end1;
        }

        ret = true;

end1:
        if(pub_buff != NULL){
            util::free(pub_buff);
        }
        fp_uninit(&x);
        fp_uninit(&y);
    }

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_PublicKey> OpECC_PrivateToPublic(Datasource& ds, const component::CurveType& curveType, const component::Bignum& _priv) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    libecc_detail::global_ds = &ds;
    uint8_t* out = nullptr;
    const ec_str_params* curve_params;
    ec_params params;
    ec_alg_type sig_type;
    ec_priv_key priv;
    ec_pub_key pub;
    std::optional<std::vector<uint8_t>> priv_bytes;
    /* Load curve.
     * NOTE: this will be WEI25519 or WEI448 (libecc uses isogenies for ed25519, ed448, x25519 and x448)
     * for EdDSA and X25519/X448
     */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    /* EdDSA case is apart */
    if ( curveType.Is(CF_ECC_CURVE("ed25519")) || curveType.Is(CF_ECC_CURVE("ed448")) ) {
        u8 key_size = 0;
        u8 pub_buff[57];
        if ( curveType.Is(CF_ECC_CURVE("ed25519")) ) {
            sig_type = EDDSA25519;
            key_size = 32;
        } else {
            sig_type = EDDSA448;
            key_size = 57;
        }
        CF_CHECK_NE(priv_bytes = util::DecToBin(_priv.ToTrimmedString(), key_size), std::nullopt);
        /* Import our private key */
        CF_ASSERT(!eddsa_import_priv_key(&priv, priv_bytes->data(), priv_bytes->size(), &params, sig_type), "eddsa_import_priv_key error " __FILE__ ":" TOSTRING(__LINE__));
        /* Import our public key */
        memset(&pub, 0, sizeof(pub));
        CF_ASSERT(!eddsa_init_pub_key(&pub, &priv), "eddsa_init_pub_key error" __FILE__ ":" TOSTRING(__LINE__));
        /* Export our public key to a buffer */
        memset(&pub_buff, 0, sizeof(pub_buff));
        CF_ASSERT(!eddsa_export_pub_key(&pub, pub_buff, key_size), "eddsa_export_pub_key error" __FILE__ ":" TOSTRING(__LINE__));
        /* Now export to a big int */
        {
            ret = { util::BinToDec(pub_buff, key_size), "0" };
        }
    }
    /* X25519/X448 case is apart */
    else if ( curveType.Is(CF_ECC_CURVE("x25519")) || curveType.Is(CF_ECC_CURVE("x448")) ) {
        u8 key_size = 0;
        u8 pub_buff[56];
        if ( curveType.Is(CF_ECC_CURVE("x25519")) ) {
            key_size = 32;
        } else {
            key_size = 56;
        }
        CF_CHECK_NE(priv_bytes = util::DecToBin(_priv.ToTrimmedString(), key_size), std::nullopt);
        /* Derive our public key */
        memset(&pub_buff, 0, sizeof(pub_buff));
        if(key_size == 32){
            CF_ASSERT(!x25519_init_pub_key(priv_bytes->data(), pub_buff), "x25519_init_pub_key error" __FILE__ ":" TOSTRING(__LINE__));
        }
        else{
            CF_ASSERT(!x448_init_pub_key(priv_bytes->data(), pub_buff), "x448_init_pub_key error" __FILE__ ":" TOSTRING(__LINE__));
        }
        /* Now export to a big int */
        {
            ret = { util::BinToDec(pub_buff, key_size), "0" };
        }
    }
    else {
        CF_CHECK_NE(priv_bytes = util::DecToBin(_priv.ToTrimmedString()), std::nullopt);
        CF_CHECK_LTE(8 * priv_bytes->size(), NN_USABLE_MAX_BIT_LEN);

        sig_type = libecc_detail::sm_ecdsa->type;

        CF_ASSERT(!ec_priv_key_import_from_buf(&priv, &params, priv_bytes->data(), priv_bytes->size(), sig_type), "ec_priv_key_import_from_buf error " __FILE__ ":" TOSTRING(__LINE__));
        memset(&pub, 0, sizeof(pub));
        CF_CHECK_EQ(init_pubkey_from_privkey(&pub, &priv), 0);
        CF_CHECK_EQ(pub.magic, PUB_KEY_MAGIC);

        /* Get the unique affine point representation */
        /* prj_pt_unique can fail if scalar is 0 or multiple of curve order */
        /* TODO assert that IF it fails, it's because of this reason */
        CF_CHECK_EQ(prj_pt_unique(&pub.y, &pub.y), 0);

        {
            const auto _ret = libecc_detail::To_Component_BignumPair(pub);
            CF_CHECK_TRUE(_priv.IsLessThan(*cryptofuzz::repository::ECC_CurveToOrder(curveType.Get())));
            ret = _ret;
        }
    }
end:
    util::free(out);

    libecc_detail::global_ds = nullptr;

    return ret;
}
}

std::optional<component::ECC_PublicKey> libecc::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    return libecc_detail::OpECC_PrivateToPublic(ds, op.curveType, op.priv);
}


namespace libecc_detail {

    typedef int (*ecxdsa_sign_raw_t)(struct ec_sign_context *ctx, const u8 *input, u8 inputlen, u8 *sig, u8 siglen, const u8 *nonce, u8 noncelen);
    typedef int (*ecxdsa_sign_update_t)(struct ec_sign_context *ctx, const u8 *chunk, u32 chunklen);
    typedef int (*ecxdsa_sign_finalize_t)(struct ec_sign_context *ctx, u8 *sig, u8 siglen);
    typedef int (*ecxdsa_rfc6979_sign_finalize_t)(struct ec_sign_context *ctx, u8 *sig, u8 siglen, ec_alg_type key_type);

    template <class Operation, ec_alg_type AlgType>
    std::optional<component::ECDSA_Signature> ECxDSA_Sign(
            const Operation& op,
            const ecxdsa_sign_raw_t ecxdsa_sign_raw,
            const ecxdsa_sign_update_t ecxdsa_sign_update,
            const ecxdsa_sign_finalize_t ecxdsa_sign_finalize,
            const ecxdsa_rfc6979_sign_finalize_t ecxdsa_rfc6979_sign_finalize = nullptr) {
        /* ecdsa_sign_raw supports messages up to 255 bytes */
        if ( op.cleartext.GetSize() > 255 ) {
            return std::nullopt;
        }

        if ( op.UseRFC6979Nonce() && ecxdsa_rfc6979_sign_finalize == nullptr ) {
            return std::nullopt;
        }

        std::optional<component::ECDSA_Signature> ret = std::nullopt;

        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::ECC_PublicKey> pub = std::nullopt;
        const ec_str_params* curve_params;
        std::optional<std::vector<uint8_t>> priv_bytes;
        ec_params params;
        ec_key_pair kp;
        struct ec_sign_context ctx;
        size_t signature_size = 0;
        uint8_t* signature = nullptr;
        std::optional<std::vector<uint8_t>> nonce_bytes;
        std::optional<hash_alg_type> hash;
        util::Multipart parts;
        const ec_alg_type alg = op.UseRFC6979Nonce() ? DECDSA : AlgType;

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_TRUE(op.UseRandomNonce() || op.UseRFC6979Nonce());
            CF_CHECK_NE(hash = libecc_detail::To_hash_alg_type(op.digestType.Get()), std::nullopt);
        } else {
            CF_CHECK_TRUE(op.UseSpecifiedNonce());
        }

        CF_CHECK_NE(pub = libecc_detail::OpECC_PrivateToPublic(ds, op.curveType, op.priv), std::nullopt);

        libecc_detail::global_ds = &ds;

        /* Load curve */
        CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
        CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

        {
            const auto priv_str = op.priv.ToTrimmedString();
            CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str), std::nullopt);
            CF_CHECK_LTE((8 * priv_bytes->size()), NN_USABLE_MAX_BIT_LEN);
            CF_CHECK_EQ(ec_key_pair_import_from_priv_key_buf(&kp,
                        &params,
                        priv_bytes->data(), priv_bytes->size(),
                        alg), 0);
        }

        signature_size = ECDSA_SIGLEN(kp.priv_key.params->ec_gen_order_bitlen);
        CF_ASSERT((signature_size % 2) == 0, "Signature size is not multiple of 2");
        signature = util::malloc(signature_size);

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_EQ(ec_sign_init(&ctx, &kp, alg, SHA256, nullptr, 0), 0);
        } else {
            CF_CHECK_EQ(ec_sign_init(&ctx, &kp, alg, *hash, nullptr, 0), 0);
        }

        if ( op.UseSpecifiedNonce() == true ) {
            /* ecdsa_sign_raw crashes if nonce is 0 */
            CF_CHECK_NE(op.nonce.ToTrimmedString(), "0");

            CF_CHECK_NE(nonce_bytes = util::DecToBin(op.nonce.ToTrimmedString()), std::nullopt);

            /* ecdsa_sign_raw supports nonce up to 255 bytes */
            CF_CHECK_LTE(nonce_bytes->size(), 255);
        }

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            parts = util::ToParts(ds, op.cleartext);
        }

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_EQ(ecxdsa_sign_raw(
                        &ctx,
                        op.cleartext.GetPtr(), op.cleartext.GetSize(),
                        signature, signature_size,
                        op.UseSpecifiedNonce() ? nonce_bytes->data() : nullptr,
                        op.UseSpecifiedNonce() ? nonce_bytes->size() : 0), 0);
        } else {
            for (const auto& part : parts) {
                CF_CHECK_EQ(ecxdsa_sign_update(&ctx, part.first, part.second), 0);
            }

            if ( op.UseRandomNonce() ) {
                CF_CHECK_EQ(ecxdsa_sign_finalize(&ctx, signature, signature_size), 0);
            } else if ( op.UseRFC6979Nonce() ) {
                CF_CHECK_EQ(ecxdsa_rfc6979_sign_finalize(&ctx, signature, signature_size, DECDSA), 0);
            } else {
                CF_UNREACHABLE();
            }
        }

        {
            auto sig = component::ECDSA_Signature{
                {
                    util::BinToDec(signature, signature_size / 2),
                        util::BinToDec(signature + (signature_size / 2), signature_size / 2),
                },
                *pub
            };

            if ( AlgType == ECDSA ) {
                CF_NORET(util::AdjustECDSASignature(op.curveType.Get(), sig.signature.second));
            }

            ret = sig;
        }

end:
        util::free(signature);

        libecc_detail::global_ds = nullptr;
        return ret;
    }

    typedef int (*ecxdsa_verify_raw_t)(struct ec_verify_context *ctx, const u8 *input, u8 inputlen);
    typedef int (*ecxdsa_verify_update_t)(struct ec_verify_context *ctx, const u8 *chunk, u32 chunklen);
    typedef int (*ecxdsa_verify_finalize_t)(struct ec_verify_context *ctx);

    template <class Operation, ec_alg_type AlgType>
    std::optional<bool> ECxDSA_Verify(
            const Operation& op,
            const ec_sig_mapping* sm,
            const ecxdsa_verify_raw_t ecxdsa_verify_raw,
            const ecxdsa_verify_update_t ecxdsa_verify_update,
            const ecxdsa_verify_finalize_t ecxdsa_verify_finalize) {
        /* ecdsa_verify_raw supports messages up to 255 bytes */
        if ( op.cleartext.GetSize() > 255 ) {
            return std::nullopt;
        }

        std::optional<bool> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        libecc_detail::global_ds = &ds;

        const ec_str_params* curve_params;
        ec_params params;
        struct ec_verify_context ctx;
        ec_key_pair kp;
        std::vector<uint8_t> pub;
        std::vector<uint8_t> sig;
        std::optional<std::vector<uint8_t>> X, Y, Z;
        std::optional<hash_alg_type> hash;
        util::Multipart parts;

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_NE(hash = libecc_detail::To_hash_alg_type(op.digestType.Get()), std::nullopt);
        }

        /* Load curve */
        CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
        CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

        {
            const size_t signature_size = ECDSA_SIGLEN(params.ec_gen_order_bitlen);
            CF_ASSERT((signature_size % 2) == 0, "Signature size is not multiple of 2");

            std::optional<std::vector<uint8_t>> R, S;
            CF_CHECK_NE(R = util::DecToBin(op.signature.signature.first.ToTrimmedString(), signature_size / 2), std::nullopt);
            CF_CHECK_NE(S = util::DecToBin(op.signature.signature.second.ToTrimmedString(), signature_size / 2), std::nullopt);

            sig.insert(std::end(sig), std::begin(*R), std::end(*R));
            sig.insert(std::end(sig), std::begin(*S), std::end(*S));
        }

        if ( !op.digestType.Is(CF_DIGEST("NULL")) ) {
            parts = util::ToParts(ds, op.cleartext);
        }

        {
            const size_t pubSize = BYTECEIL(params.ec_curve.a.ctx->p_bitlen) * 3;
            CF_ASSERT((pubSize % 2) == 0, "Public key byte size is not even");
            CF_ASSERT((pubSize % 3) == 0, "Public key byte size is not multiple of 3");
            pub.resize(pubSize, 0);

            const size_t pointSize = pubSize / 3;
            CF_CHECK_NE(X = util::DecToBin(op.signature.pub.first.ToTrimmedString(), pointSize), std::nullopt);
            CF_CHECK_NE(Y = util::DecToBin(op.signature.pub.second.ToTrimmedString(), pointSize), std::nullopt);
            CF_CHECK_NE(Z = util::DecToBin("1", pointSize), std::nullopt);

            memcpy(pub.data(), X->data(), pointSize);
            memcpy(pub.data() + pointSize, Y->data(), pointSize);
            memcpy(pub.data() + pointSize * 2, Z->data(), pointSize);

            CF_CHECK_EQ(ec_pub_key_import_from_buf(
                        &kp.pub_key,
                        &params,
                        pub.data(), pub.size(),
                        sm->type), 0);

            int check;
            CF_ASSERT(!prj_pt_is_on_curve(&kp.pub_key.y, &check), "prj_pt_is_on_curve error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_EQ(check, 1);
        }

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            CF_CHECK_EQ(ec_verify_init(&ctx, &(kp.pub_key), sig.data(), sig.size(), AlgType, SHA256, nullptr, 0), 0);
        } else {
            CF_CHECK_EQ(ec_verify_init(&ctx, &(kp.pub_key), sig.data(), sig.size(), AlgType, *hash, nullptr, 0), 0);
        }

        if ( op.digestType.Is(CF_DIGEST("NULL")) ) {
            const auto cleartext_ptr = op.cleartext.GetPtr();

            /* libecc has an explicit check for NULL input which causes ecdsa_verify_raw
             * to return false even if the signature is valid.
             *
             * See also OSS-Fuzz issue #33808
             */
            CF_CHECK_NE(cleartext_ptr, nullptr);

            ret = ecxdsa_verify_raw(&ctx, cleartext_ptr, op.cleartext.GetSize()) == 0;
        } else {
            for (const auto& part : parts) {
                CF_CHECK_EQ(ecxdsa_verify_update(&ctx, part.first, part.second), 0);
            }

            ret = ecxdsa_verify_finalize(&ctx) == 0;
        }

end:
        libecc_detail::global_ds = nullptr;

        return ret;
    }
} /* namespace libecc_detail */


/* EdDSA cases */
namespace libecc_detail {
    std::optional<component::ECDSA_Signature> EdDSA_Sign(operation::ECDSA_Sign& op) {
        ec_key_pair kp;
        const ec_str_params* curve_params;
        ec_params params;
        ec_alg_type sig_type;
        hash_alg_type hash_type;
        uint8_t* signature = nullptr;
        std::optional<component::ECDSA_Signature> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        std::optional<component::ECC_PublicKey> pub = std::nullopt;
        libecc_detail::global_ds = &ds;
        u8 key_size = 0;
        u8 siglen;

        /* Load curve.
         * NOTE: this will be WEI25519 or WEI448 (libecc uses isogenies for ed25519, ed448, x25519 and x448)
         */
        CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
        CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

        if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) ){
            /* Ed25519 case */
            key_size = 32;
            sig_type = EDDSA25519;
            if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHA512")) ) {
                return std::nullopt;
            }
            hash_type = SHA512;
        }
        else if ( op.curveType.Is(CF_ECC_CURVE("ed448")) ){
            /* Ed448 case */
            key_size = 56;
            sig_type = EDDSA448;
            if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHAKE256_114")) ) {
                return std::nullopt;
            }
            hash_type = SHAKE256;
        }
        else{
            goto end;
        }
        {
            /* Extract the private key */
            const auto _priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), key_size);
            if ( (_priv_bytes == std::nullopt) || (_priv_bytes->size() != key_size) ) {
                return std::nullopt;
            }
            /* Import our key pair */
   	    CF_CHECK_EQ(eddsa_import_key_pair_from_priv_key_buf(&kp, _priv_bytes->data(), key_size, &params, sig_type), 0);
  	    /* Now sign */
            siglen = (2 * key_size);
            signature = util::malloc(siglen);
            /* In case of NULL pointer as cleartext, replace it by an empty string with the same size */
            if(op.cleartext.GetPtr() == NULL){
                const unsigned char msg[] = "";
  	        CF_CHECK_EQ(_ec_sign(signature, siglen, &kp, msg, 0, nullptr, sig_type, hash_type, nullptr, 0), 0);
            }
            else{
  	        CF_CHECK_EQ(_ec_sign(signature, siglen, &kp, op.cleartext.GetPtr(), op.cleartext.GetSize(), nullptr, sig_type, hash_type, nullptr, 0), 0);
            }
        }
        /* Get the public key */
        CF_CHECK_NE(pub = libecc_detail::OpECC_PrivateToPublic(ds, op.curveType, op.priv), std::nullopt);

        ret = {
            {
                util::BinToDec(signature, siglen / 2),
                util::BinToDec(signature + (siglen / 2), siglen / 2),
            },
            *pub
        };
end:
        util::free(signature);
        libecc_detail::global_ds = nullptr;

        return ret;
    }
    /***************************************************************************/
    std::optional<bool> EdDSA_Verify(operation::ECDSA_Verify& op) {
        std::optional<bool> ret = std::nullopt;
        Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());
        libecc_detail::global_ds = &ds;

        const ec_str_params* curve_params;
        ec_params params;
        struct ec_verify_context ctx;
        ec_pub_key pub_key;
        std::optional<std::vector<uint8_t>> pub;
        std::vector<uint8_t> sig;
        u8 key_size = 0;
        ec_alg_type sig_type;
        hash_alg_type hash_type;
        bool oneShot = true;

        /* Streaming mode or not? */
        try { oneShot = ds.Get<bool>(); } catch ( ... ) { }

        /* Load curve.
         * NOTE: this will be WEI25519 or WEI448 (libecc uses isogenies for ed25519, ed448, x25519 and x448)
         */
        CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
        CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

        if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) ){
            /* Ed25519 case */
            key_size = 32;
            sig_type = EDDSA25519;
            if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHA512")) ) {
                return std::nullopt;
            }
            hash_type = SHA512;
        }
        else if ( op.curveType.Is(CF_ECC_CURVE("ed448")) ){
            /* Ed448 case */
            key_size = 56;
            sig_type = EDDSA448;
            if ( !op.digestType.Is(CF_DIGEST("NULL")) && !op.digestType.Is(CF_DIGEST("SHAKE256_114")) ) {
                return std::nullopt;
            }
            hash_type = SHAKE256;
        }
        else{
            goto end;
        }

        {
            /* Extract our signature */
            const size_t signature_size = (2 * key_size);
            CF_ASSERT((signature_size % 2) == 0, "Signature size is not multiple of 2");

            std::optional<std::vector<uint8_t>> R, S;
            CF_CHECK_NE(R = util::DecToBin(op.signature.signature.first.ToTrimmedString(), signature_size / 2), std::nullopt);
            CF_CHECK_NE(S = util::DecToBin(op.signature.signature.second.ToTrimmedString(), signature_size / 2), std::nullopt);

            sig.insert(std::end(sig), std::begin(*R), std::end(*R));
            sig.insert(std::end(sig), std::begin(*S), std::end(*S));
        }

        {
            /* Extract the public key */
            CF_CHECK_NE(pub = util::DecToBin(op.signature.pub.first.ToTrimmedString(), key_size), std::nullopt);
            /* Import it */
            CF_CHECK_EQ(eddsa_import_pub_key(&pub_key, (*pub).data(), (*pub).size(), &params, sig_type), 0);
        }

        /* Proceed with the verification */
        if ( oneShot == true ) {
            /* Non streaming mode */
            /* In case of NULL pointer as cleartext, replace it by an empty string with the same size */
            if(op.cleartext.GetPtr() == NULL){
                const unsigned char msg[] = "";
                ret = ec_verify(sig.data(), sig.size(), &pub_key, msg, 0, sig_type, hash_type, nullptr, 0) == 0;
            }
            else{
                ret = ec_verify(sig.data(), sig.size(), &pub_key, op.cleartext.GetPtr(), op.cleartext.GetSize(), sig_type, hash_type, nullptr, 0) == 0;
            }
        }
        else{
            /* Sreaming mode */
            const auto parts = util::ToParts(ds, op.cleartext);
            CF_CHECK_EQ(ec_verify_init(&ctx, &pub_key, sig.data(), sig.size(), sig_type, hash_type, nullptr, 0), 0);

            for (const auto& part : parts) {
                CF_CHECK_EQ(ec_verify_update(&ctx, part.first, part.second), 0);
            }

            ret = ec_verify_finalize(&ctx) == 0;
        }

end:
        libecc_detail::global_ds = nullptr;

        return ret;
    }
} /* namespace libecc_detail */


/*************************/
std::optional<component::ECDSA_Signature> libecc::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) || op.curveType.Is(CF_ECC_CURVE("ed448")) ) {
        /* EdDSA cases */
        return libecc_detail::EdDSA_Sign(op);
    }
    else{
        /* ECxDSA cases */
        return libecc_detail::ECxDSA_Sign<operation::ECDSA_Sign, ECDSA>(op, ecdsa_sign_raw, _ecdsa_sign_update, _ecdsa_sign_finalize, __ecdsa_sign_finalize);
    }
}

std::optional<component::ECGDSA_Signature> libecc::OpECGDSA_Sign(operation::ECGDSA_Sign& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) || op.curveType.Is(CF_ECC_CURVE("ed448")) ) {
        /* EdDSA does not make sense in OpECGDSA_Sign */
        return std::nullopt;
    }
    else{
        return libecc_detail::ECxDSA_Sign<operation::ECGDSA_Sign, ECGDSA>(op, ecgdsa_sign_raw, _ecgdsa_sign_update, _ecgdsa_sign_finalize);
    }
}

std::optional<component::ECRDSA_Signature> libecc::OpECRDSA_Sign(operation::ECRDSA_Sign& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) || op.curveType.Is(CF_ECC_CURVE("ed448")) ) {
        /* EdDSA does not make sense in OpECRDSA_Sign */
        return std::nullopt;
    }
    else{
        return libecc_detail::ECxDSA_Sign<operation::ECRDSA_Sign, ECRDSA>(op, ecrdsa_sign_raw, _ecrdsa_sign_update, _ecrdsa_sign_finalize);
    }
}

std::optional<bool> libecc::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) || op.curveType.Is(CF_ECC_CURVE("ed448")) ) {
        /* EdDSA cases */
        return libecc_detail::EdDSA_Verify(op);
    }
    else{
        return libecc_detail::ECxDSA_Verify<operation::ECDSA_Verify, ECDSA>(op, libecc_detail::sm_ecdsa, ecdsa_verify_raw, _ecdsa_verify_update, _ecdsa_verify_finalize);
    }
}

std::optional<bool> libecc::OpECGDSA_Verify(operation::ECGDSA_Verify& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) || op.curveType.Is(CF_ECC_CURVE("ed448")) ) {
        /* EdDSA does not make sense in OpECGDSA_Verify */
        return std::nullopt;
    }
    else{
        return libecc_detail::ECxDSA_Verify<operation::ECGDSA_Verify, ECGDSA>(op, libecc_detail::sm_ecgdsa, ecgdsa_verify_raw, _ecgdsa_verify_update, _ecgdsa_verify_finalize);
    }
}

std::optional<bool> libecc::OpECRDSA_Verify(operation::ECRDSA_Verify& op) {
    if ( op.curveType.Is(CF_ECC_CURVE("ed25519")) || op.curveType.Is(CF_ECC_CURVE("ed448")) ) {
        /* EdDSA does not make sense in OpECRDSA_Verify */
        return std::nullopt;
    }
    else{
        return libecc_detail::ECxDSA_Verify<operation::ECRDSA_Verify, ECRDSA>(op, libecc_detail::sm_ecrdsa, ecrdsa_verify_raw, _ecrdsa_verify_update, _ecrdsa_verify_finalize);
    }
}

namespace libecc_detail {
    bool LoadPoint(
            fuzzing::datasource::Datasource& ds,
            const component::ECC_Point in,
            prj_pt& out,
            const ec_params& params,
            const component::CurveType curveType) {
        bool ret = false;
        fp x, y, z;

        bool projective = false;
        try {
            projective = ds.Get<bool>();
        } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

        if ( projective == false ) {
            const auto x_bin = util::DecToBin(in.first.ToTrimmedString());
            const auto y_bin = util::DecToBin(in.second.ToTrimmedString());

            CF_CHECK_TRUE(!fp_init_from_buf(&x, &(params.ec_fp), x_bin->data(), x_bin->size()));
            CF_CHECK_TRUE(!fp_init_from_buf(&y, &(params.ec_fp), y_bin->data(), y_bin->size()));
            CF_ASSERT(!fp_init(&z, &(params.ec_fp)), "fp_init error " __FILE__ ":" TOSTRING(__LINE__));
            CF_ASSERT(!fp_one(&z), "fp_one error " __FILE__ ":" TOSTRING(__LINE__));
            CF_CHECK_TRUE(!prj_pt_init_from_coords(&out, &(params.ec_curve), &x, &y, &z));
        } else {
            const auto proj = util::ToRandomProjective(
                    ds,
                    in.first.ToTrimmedString(),
                    in.second.ToTrimmedString(),
                    curveType.Get(),
                    false /* not jacobian */);

            const auto x_bin = util::DecToBin(proj[0]);
            const auto y_bin = util::DecToBin(proj[1]);
            const auto z_bin = util::DecToBin(proj[2]);

            CF_CHECK_TRUE(!fp_init_from_buf(&x, &(params.ec_fp), x_bin->data(), x_bin->size()));
            CF_CHECK_TRUE(!fp_init_from_buf(&y, &(params.ec_fp), y_bin->data(), y_bin->size()));
            CF_CHECK_TRUE(!fp_init_from_buf(&z, &(params.ec_fp), z_bin->data(), z_bin->size()));
            CF_CHECK_TRUE(!prj_pt_init_from_coords(&out, &(params.ec_curve), &x, &y, &z));
        }

        ret = true;
end:
        return ret;
    }

    std::optional<component::ECC_Point> SavePoint(
            const prj_pt& res,
            const ec_params& params) {
        std::optional<component::ECC_Point> ret = std::nullopt;

        aff_pt res_aff;

        CF_CHECK_TRUE(!prj_pt_to_aff(&res_aff, &res));

        {
            const size_t coordinateSize = BYTECEIL(params.ec_curve.a.ctx->p_bitlen);
            const size_t pointSize = coordinateSize * 2;

            uint8_t out_bytes[pointSize];

            CF_CHECK_EQ(aff_pt_export_to_buf(&res_aff, out_bytes, pointSize), 0);

            const auto X = util::BinToDec(out_bytes, coordinateSize);
            const auto Y = util::BinToDec(out_bytes + coordinateSize, coordinateSize);

            ret = {X, Y};
        }

end:
        return ret;
    }
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Add(operation::ECC_Point_Add& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    libecc_detail::global_ds = &ds;

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a, b;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    CF_ASSERT(!prj_pt_init(&res, &(params.ec_curve)), "prj_pt_init error " __FILE__ ":" TOSTRING(__LINE__));

    /* Load points */
    CF_CHECK_TRUE(libecc_detail::LoadPoint(ds, op.a, a, params, op.curveType));
    CF_CHECK_TRUE(libecc_detail::LoadPoint(ds, op.b, b, params, op.curveType));

    /* Add points */
    CF_CHECK_TRUE(!prj_pt_add(&res, &a, &b));

    /* Save result */
    ret = libecc_detail::SavePoint(res, params);

    prj_pt_uninit(&res);
    prj_pt_uninit(&a);
    prj_pt_uninit(&b);

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Mul(operation::ECC_Point_Mul& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a;
    nn b;

    libecc_detail::global_ds = &ds;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    CF_ASSERT(!prj_pt_init(&res, &(params.ec_curve)), "prj_pt_init error " __FILE__ ":" TOSTRING(__LINE__));

    /* Load point */
    CF_CHECK_TRUE(libecc_detail::LoadPoint(ds, op.a, a, params, op.curveType));

    /* Load scalar */
    CF_CHECK_TRUE(libecc_detail::To_nn_t(op.b, &b));

    /* Multiply point by scalar */
    CF_CHECK_TRUE(!prj_pt_mul(&res, &b, &a));

    /* Save result */
    ret = libecc_detail::SavePoint(res, params);

    prj_pt_uninit(&res);
    prj_pt_uninit(&a);

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Dbl(operation::ECC_Point_Dbl& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a;

    libecc_detail::global_ds = &ds;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    CF_ASSERT(!prj_pt_init(&res, &(params.ec_curve)), "prj_pt_init error " __FILE__ ":" TOSTRING(__LINE__));

    /* Load point */
    CF_CHECK_TRUE(libecc_detail::LoadPoint(ds, op.a, a, params, op.curveType));

    /* Double */
    CF_CHECK_TRUE(!prj_pt_dbl(&res, &a));

    /* Save result */
    ret = libecc_detail::SavePoint(res, params);

    prj_pt_uninit(&res);
    prj_pt_uninit(&a);

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::ECC_Point> libecc::OpECC_Point_Neg(operation::ECC_Point_Neg& op) {
    std::optional<component::ECC_Point> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt res, a;

    libecc_detail::global_ds = &ds;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    CF_ASSERT(!prj_pt_init(&res, &(params.ec_curve)), "prj_pt_init error " __FILE__ ":" TOSTRING(__LINE__));

    /* Load point */
    CF_CHECK_TRUE(libecc_detail::LoadPoint(ds, op.a, a, params, op.curveType));

    /* Negate */
    CF_CHECK_TRUE(!prj_pt_neg(&res, &a));

    /* Save result */
    ret = libecc_detail::SavePoint(res, params);

    prj_pt_uninit(&res);
    prj_pt_uninit(&a);

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<bool> libecc::OpECC_Point_Cmp(operation::ECC_Point_Cmp& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    libecc_detail::global_ds = &ds;

    const ec_str_params* curve_params;
    ec_params params;
    prj_pt a, b;
    int cmp;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    /* Load points */
    CF_CHECK_TRUE(libecc_detail::LoadPoint(ds, op.a, a, params, op.curveType));
    CF_CHECK_TRUE(libecc_detail::LoadPoint(ds, op.b, b, params, op.curveType));


    CF_CHECK_TRUE(!prj_pt_cmp(&a, &b, &cmp));
    ret = cmp == 0;

    prj_pt_uninit(&a);
    prj_pt_uninit(&b);

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

std::optional<component::Secret> libecc::OpECDH_Derive(operation::ECDH_Derive& op) {
    std::optional<component::Secret> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    libecc_detail::global_ds = &ds;

    const ec_str_params* curve_params;
    ec_params params;

    /* Extract the private key */
    std::optional<std::vector<uint8_t>> priv_bytes;
    std::string priv_str;
    priv_str = op.priv.ToTrimmedString();
    CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str), std::nullopt);
    CF_CHECK_LTE((8 * priv_bytes->size()), NN_USABLE_MAX_BIT_LEN);

    /* Load curve.
     * NOTE: this will be WEI25519 or WEI448 (libecc uses isogenies for ed25519, ed448, x25519 and x448).
     * Our underlying X25519 and X448 operations will perform these isogenies transparently.
     */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    CF_ASSERT(!import_params(&params, curve_params), "import_params error " __FILE__ ":" TOSTRING(__LINE__));

    if ( op.curveType.Is(CF_ECC_CURVE("x25519")) ){
        u8 shared_secret[X25519_SIZE];
        std::optional<std::vector<uint8_t>> pub;
        /* X25519 case, check sizes */
        CF_CHECK_EQ(priv_bytes->size(), X25519_SIZE);
        /* Import the peer public key in a buffer */
        CF_CHECK_NE(pub = util::DecToBin(op.pub.first.ToTrimmedString(), X25519_SIZE), std::nullopt);
        /* Derive our secret */
        CF_CHECK_EQ(x25519_derive_secret(priv_bytes->data(), pub->data(), shared_secret), 0);
	/* Return the shared secret */
        ret = component::Secret(Buffer(shared_secret, X25519_SIZE));
    }
    else if ( op.curveType.Is(CF_ECC_CURVE("x448")) ){
        u8 shared_secret[X448_SIZE];
        std::optional<std::vector<uint8_t>> pub;
        /* X448 case, check size */
        CF_CHECK_EQ(priv_bytes->size(), X448_SIZE);
        /* Import the peer public key in a buffer */
        CF_CHECK_NE(pub = util::DecToBin(op.pub.first.ToTrimmedString(), X448_SIZE), std::nullopt);
        /* Derive our secret */
        CF_CHECK_EQ(x448_derive_secret(priv_bytes->data(), pub->data(), shared_secret), 0);
	/* Return the shared secret */
        ret = component::Secret(Buffer(shared_secret, X448_SIZE));
    }
    else{
        /* ECCDH generic case */
        ec_priv_key priv;
        std::vector<uint8_t> pub;
        u8 size;
        u8 shared_secret[1024];

        /* Get the size of our shared secret depending on the curve */
        CF_CHECK_EQ(ecccdh_shared_secret_size(&params, &size), 0);

        /* Import our private key */
        CF_ASSERT(!ec_priv_key_import_from_buf(&priv, &params, priv_bytes->data(), priv_bytes->size(), ECCCDH), "ec_priv_key_import_from_buf error " __FILE__ ":" TOSTRING(__LINE__));
        /* Import the peer public key in a buffer */
        std::optional<std::vector<uint8_t>> X, Y;
        const size_t pubSize = BYTECEIL(params.ec_curve.a.ctx->p_bitlen) * 3;
        CF_ASSERT((pubSize % 2) == 0, "Public key byte size is not even");
        CF_ASSERT((pubSize % 3) == 0, "Public key byte size is not multiple of 3");

        const size_t pointSize = pubSize / 3;
        CF_CHECK_NE(X = util::DecToBin(op.pub.first.ToTrimmedString(), pointSize), std::nullopt);
        CF_CHECK_NE(Y = util::DecToBin(op.pub.second.ToTrimmedString(), pointSize), std::nullopt);

        pub.resize((2 * pointSize), 0);
        memcpy(pub.data(), X->data(), pointSize);
        memcpy(pub.data() + pointSize, Y->data(), pointSize);

	/* Compute the shared secret */
        CF_CHECK_EQ(ecccdh_derive_secret(&priv, pub.data(), pub.size(), shared_secret, size), 0);

	/* Return the shared secret */
        ret = component::Secret(Buffer(shared_secret, size));
    }

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

namespace libecc_detail {
    static std::optional<word_t> ToWord(const component::Bignum& bn) {
        try {
            return boost::lexical_cast<word_t>(bn.ToTrimmedString());
        } catch ( const boost::bad_lexical_cast &e ) {
            return std::nullopt;
        }
    }

    class Bignum {
        private:
            nn v;
        public:
            Bignum(void) {
                CF_ASSERT(
                        !nn_init(&v, 0),
                        "nn_init error " __FILE__ ":" TOSTRING(__LINE__));
            }

            ~Bignum() { }

            bool Set(const component::Bignum& bn) {
                return To_nn_t(bn, &v);
            }

            nn_t GetPtr(void) {
                return &v;
            }

            std::optional<component::Bignum> ToComponentBignum(void) {
                return To_Component_Bignum(&v);
            }

            inline int Cmp(const Bignum& rhs) {
                int check;
                CF_ASSERT(
                        !nn_cmp(&v, &rhs.v, &check),
                        "nn_cmp error " __FILE__ ":" TOSTRING(__LINE__));
                return check;
            }
            inline bool operator==(const Bignum& rhs) {
                return Cmp(rhs) == 0;
            }

            inline bool operator>(const Bignum& rhs) {
                return Cmp(rhs) > 0;
            }

            void SetZero(void) {
                CF_ASSERT(
                        !nn_zero(&v),
                        "nn_zero error " __FILE__ ":" TOSTRING(__LINE__));
            }

            void SetOne(void) {
                CF_ASSERT(
                        !nn_one(&v),
                        "nn_one error " __FILE__ ":" TOSTRING(__LINE__));
            }

            void SetWord(const word_t w) {
                CF_ASSERT(
                        !nn_set_word_value(&v, w),
                        "nn_set_word error " __FILE__ ":" TOSTRING(__LINE__));
            }

            bool IsZero(void) {
                int check;
                CF_ASSERT(
                        !nn_iszero(&v, &check),
                        "nn_iszero error " __FILE__ ":" TOSTRING(__LINE__));
                return check == 1;
            }

            bool IsOne(void) {
                int check;
                CF_ASSERT(
                        !nn_isone(&v, &check),
                        "nn_isone error " __FILE__ ":" TOSTRING(__LINE__));
                return check == 1;
            }

            bool IsOdd(void) {
                int check;
                CF_ASSERT(
                        !nn_isodd(&v, &check),
                        "nn_isodd error " __FILE__ ":" TOSTRING(__LINE__));
                return check == 1;
            }

            bitcnt_t NumBits(void) {
                bitcnt_t numbits;
                CF_ASSERT(
                        !nn_bitlen(&v, &numbits),
                        "nn_bitlen error " __FILE__ ":" TOSTRING(__LINE__));
                return numbits;
            }
    };

    class BignumCluster {
        private:
            Datasource& ds;
            std::array<Bignum, 4> bn;
            std::optional<size_t> res_index = std::nullopt;
        public:
            BignumCluster(Datasource& ds, Bignum bn0, Bignum bn1, Bignum bn2, Bignum bn3) :
                ds(ds),
                bn({bn0, bn1, bn2, bn3})
                { }

            Bignum& operator[](const size_t index) {
                if ( index >= bn.size() ) {
                    abort();
                }

                try {
                    /* Rewire? */
                    if ( ds.Get<bool>() == true ) {
                        /* Pick a random bignum */
                        const size_t newIndex = ds.Get<uint8_t>() % 4;

                        /* Same value? */
                        if ( bn[newIndex] == bn[index] ) {
                            /* Then return reference to other bignum */
                            return bn[newIndex];
                        }

                        /* Fall through */
                    }
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                return bn[index];
            }

            Bignum& Get(const size_t index) {
                if ( index >= bn.size() ) {
                    abort();
                }

                return bn[index];
            }

            bool Set(const size_t index, const component::Bignum& v) {
                if ( index >= bn.size() ) {
                    abort();
                }

                return bn[index].Set(v);
            }

            nn_t GetResPtr(void) {
                CF_ASSERT(res_index == std::nullopt, "Reusing result pointer");

                res_index = 0;

                try { res_index = ds.Get<uint8_t>() % 4; }
                catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                return bn[*res_index].GetPtr();
            }

            void CopyResult(Bignum& res) {
                CF_ASSERT(res_index != std::nullopt, "Result index is undefined");

                const auto src = bn[*res_index].GetPtr();
                auto dest = res.GetPtr();

                CF_ASSERT(
                        !nn_copy(dest, src),
                        "nn_copy error " __FILE__ ":" TOSTRING(__LINE__));
            }
    };
}

std::optional<component::Bignum> libecc::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    libecc_detail::global_ds = &ds;

    libecc_detail::Bignum result;
    libecc_detail::BignumCluster bn{ds,
        libecc_detail::Bignum(),
        libecc_detail::Bignum(),
        libecc_detail::Bignum(),
        libecc_detail::Bignum()
    };
    bool negative = false;

    if ( repository::CalcOpToNumParams(op.calcOp.Get()) > 0 ) {
        CF_CHECK_TRUE(bn.Set(0, op.bn0));
    }
    if ( repository::CalcOpToNumParams(op.calcOp.Get()) > 1 ) {
        CF_CHECK_TRUE(bn.Set(1, op.bn1));
    }
    if ( repository::CalcOpToNumParams(op.calcOp.Get()) > 2 ) {
        CF_CHECK_TRUE(bn.Set(2, op.bn2));
    }

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            {
                bool inc = false;

                if ( op.bn1.ToTrimmedString() == "1") {
                    try {
                        inc = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }
                if ( inc == false ) {
                    CF_CHECK_EQ(nn_add(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
                } else {
                    CF_CHECK_EQ(nn_inc(bn.GetResPtr(), bn[0].GetPtr()), 0);
                }
                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("Sub(A,B)"):
            {
                CF_CHECK_TRUE(bn[0] > bn[1]);

                bool dec = false;

                if ( op.bn1.ToTrimmedString() == "1") {
                    try {
                        dec = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }

                if ( dec == false ) {
                    CF_CHECK_EQ(nn_sub(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
                } else {
                    CF_CHECK_EQ(nn_dec(bn.GetResPtr(), bn[0].GetPtr()), 0);
                }
                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("LShift1(A)"):
            {
                CF_CHECK_EQ(nn_lshift(bn.GetResPtr(), bn[0].GetPtr(), 1), 0);
                CF_NORET(bn.CopyResult(result));

                CF_CHECK_LT(result.NumBits(), NN_MAX_BIT_LEN);
            }
            break;
        case    CF_CALCOP("RShift(A,B)"):
            {
                std::optional<uint16_t> count;
                CF_CHECK_NE(count = libecc_detail::To_uint16_t(op.bn1), std::nullopt);

                CF_CHECK_EQ(nn_rshift(bn.GetResPtr(), bn[0].GetPtr(), *count), 0);
                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("Mul(A,B)"):
            {
                bool mul_word = false;
                std::optional<word_t> w;

                try {
                    mul_word = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( mul_word == true ) {
                    w = libecc_detail::ToWord(op.bn1);
                    if ( w == std::nullopt ) {
                        mul_word = false;
                    }
                }

                if ( mul_word == false ) {
                    CF_CHECK_EQ(nn_mul(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
                } else {
                    CF_CHECK_EQ(nn_mul_word(bn.GetResPtr(), bn[0].GetPtr(), *w), 0);
                }

                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("Div(A,B)"):
            {
                libecc_detail::Bignum _remainder;
                nn_t remainder = bn[2].GetPtr();
                nn_t res = bn.GetResPtr();
                nn_t bn0 = bn[0].GetPtr();
                nn_t bn1 = bn[1].GetPtr();
                /* Ensure that result pointers do not overlap */
                if ( res == remainder ) {
                    remainder = _remainder.GetPtr();
                }
                CF_CHECK_EQ(nn_divrem(res, remainder, bn0, bn1), 0);
                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("GCD(A,B)"):
            {
                int sign;
                CF_CHECK_EQ(nn_gcd(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), &sign), 0);
                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("Mod(A,B)"):
            CF_CHECK_FALSE(bn[1].IsZero());
            CF_CHECK_EQ(nn_mod(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("Sqr(A)"):
            CF_CHECK_EQ(nn_sqr(bn.GetResPtr(), bn[0].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("And(A,B)"):
            CF_CHECK_EQ(nn_and(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("Or(A,B)"):
            CF_CHECK_EQ(nn_or(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("Xor(A,B)"):
            CF_CHECK_EQ(nn_xor(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("InvMod(A,B)"):
            {
                bool use_nn_modinv_2exp = false;
                bitcnt_t exponent = 0;

                try {
                    use_nn_modinv_2exp = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( use_nn_modinv_2exp == true ) {
                    /* Determine if 2^exponent == modulus */
                    const auto numbits = bn[1].NumBits();
                    if ( numbits == 0 ) {
                        use_nn_modinv_2exp = false;
                    } else {
                        size_t num_1_bits = 0;
                        for (bitcnt_t i = 0; i < numbits; i++) {
                            u8 bitval;
                            CF_ASSERT(
                                    nn_getbit(bn[1].GetPtr(), i, &bitval) == 0,
                                    "nn_getbit error " __FILE__ ":" TOSTRING(__LINE__));
                            if ( bitval ) {
                                num_1_bits++;
                                if ( num_1_bits > 1 ) {
                                    use_nn_modinv_2exp = false;
                                    break;
                                }
                            } else {
                                exponent++;
                            }
                        }
                    }
                }

                if ( use_nn_modinv_2exp == true && exponent == 0 ) {
                    /* XXX bug */
                    use_nn_modinv_2exp = false;
                }

                if ( use_nn_modinv_2exp == true ) {
                    int x_isodd;
                    CF_CHECK_EQ(
                            nn_modinv_2exp(
                                bn.GetResPtr(),
                                bn[0].GetPtr(),
                                exponent,
                                &x_isodd), 0);
                    CF_NORET(bn.CopyResult(result));
                } else {
                    if ( nn_modinv(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()) == 0 ) {
                        CF_NORET(bn.CopyResult(result));
                    } else {
                        CF_NORET(result.SetZero());
                    }
                }
            }
            break;
        case    CF_CALCOP("ExpMod(A,B,C)"):
            CF_CHECK_EQ(nn_mod_pow(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("MulMod(A,B,C)"):
            CF_CHECK_TRUE(bn[2].IsOdd());
            CF_CHECK_TRUE(bn[2] > bn[0]);
            CF_CHECK_TRUE(bn[2] > bn[1]);

            CF_CHECK_EQ(nn_mod_mul(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("AddMod(A,B,C)"):
            {
                CF_CHECK_TRUE(bn[2] > bn[0]);
                CF_CHECK_TRUE(bn[2] > bn[1]);

                bool mod_inc = false;

                if ( op.bn1.ToTrimmedString() == "1") {
                    try {
                        mod_inc = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }

                if ( mod_inc == false ) {
                    /* Aliasing bug */
                    //CF_CHECK_EQ(nn_mod_add(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 0);
                    //CF_NORET(bn.CopyResult(result));
                    CF_CHECK_EQ(nn_mod_add(result.GetPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 0);
                } else {
                    /* Aliasing bug */
                    //CF_CHECK_EQ(nn_mod_inc(bn.GetResPtr(), bn[0].GetPtr(), bn[2].GetPtr()), 0);
                    //CF_NORET(bn.CopyResult(result));

                    CF_CHECK_EQ(nn_mod_inc(result.GetPtr(), bn[0].GetPtr(), bn[2].GetPtr()), 0);
                }
            }
            break;
        case    CF_CALCOP("SubMod(A,B,C)"):
            {
                CF_CHECK_TRUE(bn[2] > bn[0]);
                CF_CHECK_TRUE(bn[2] > bn[1]);

                bool mod_dec = false;

                if ( op.bn1.ToTrimmedString() == "1") {
                    try {
                        mod_dec = ds.Get<bool>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }
                }

                if ( mod_dec == false ) {
                    CF_CHECK_EQ(nn_mod_sub(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr(), bn[2].GetPtr()), 0);
                } else {
                    CF_CHECK_EQ(nn_mod_dec(bn.GetResPtr(), bn[0].GetPtr(), bn[2].GetPtr()), 0);
                }

                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("LRot(A,B,C)"):
            {
                std::optional<uint16_t> count, bitlen;

                CF_CHECK_NE(count = libecc_detail::To_uint16_t(op.bn1), std::nullopt);
                CF_CHECK_NE(bitlen = libecc_detail::To_uint16_t(op.bn2), std::nullopt);

                CF_CHECK_EQ(nn_lrot(bn.GetResPtr(), bn[0].GetPtr(), *count, *bitlen), 0);
                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("RRot(A,B,C)"):
            {
                std::optional<uint16_t> count, bitlen;

                CF_CHECK_NE(count = libecc_detail::To_uint16_t(op.bn1), std::nullopt);
                CF_CHECK_NE(bitlen = libecc_detail::To_uint16_t(op.bn2), std::nullopt);

                CF_CHECK_EQ(nn_rrot(bn.GetResPtr(), bn[0].GetPtr(), *count, *bitlen), 0);
                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("ExtGCD_X(A,B)"):
        case    CF_CALCOP("ExtGCD_Y(A,B)"):
            {
                /* NOTE: internally, libecc should support a = 0 or b = 0. Is this test necessary?
                */
                CF_CHECK_FALSE(bn[0].IsZero());
                CF_CHECK_FALSE(bn[1].IsZero());

                int sign;

                libecc_detail::Bignum _tmp1, _tmp2;
                nn_t tmp1 = bn[2].GetPtr();
                nn_t tmp2 = bn[3].GetPtr();
                nn_t res = bn.GetResPtr();
                nn_t bn0 = bn[0].GetPtr();
                nn_t bn1 = bn[1].GetPtr();

                /* Ensure that result pointers do not overlap */
                if ( tmp1 == tmp2 || res == tmp1 || res == tmp2 ) {
                    tmp1 = _tmp1.GetPtr();
                    tmp2 = _tmp2.GetPtr();
                }

                if ( op.calcOp.Get() == CF_CALCOP("ExtGCD_X(A,B)") ) {
                    CF_CHECK_EQ(nn_xgcd(tmp1, res, tmp2, bn0, bn1, &sign), 0);
                    negative = sign == -1;
                } else {
                    CF_CHECK_EQ(nn_xgcd(tmp1, tmp2, res, bn0, bn1, &sign), 0);
                    negative = sign == 1;
                }

                CF_NORET(bn.CopyResult(result));
            }
            break;
        case    CF_CALCOP("IsZero(A)"):
            bn[0].IsZero() ? result.SetOne() : result.SetZero();
            break;
        case    CF_CALCOP("IsOne(A)"):
            bn[0].IsOne() ? result.SetOne() : result.SetZero();
            break;
        case    CF_CALCOP("IsOdd(A)"):
            bn[0].IsOdd() ? result.SetOne() : result.SetZero();
            break;
        case    CF_CALCOP("NumBits(A)"):
            {
                const auto numbits = bn[0].NumBits();

                static_assert(sizeof(numbits) <= sizeof(word_t));
                CF_NORET(result.SetWord(numbits));
            }
            break;
        case    CF_CALCOP("Bit(A,B)"):
            try {
                const auto count = boost::lexical_cast<bitcnt_t>(op.bn1.ToTrimmedString());

                u8 bitval;
                CF_CHECK_EQ(nn_getbit(bn[0].GetPtr(), count, &bitval), 0);

                static_assert(sizeof(bitval) <= sizeof(word_t));
                CF_NORET(result.SetWord(bitval));
            } catch ( const boost::bad_lexical_cast &e ) {
            }
            break;
        case    CF_CALCOP("Cmp(A,B)"):
            {
                bool cmp_word = false;
                std::optional<word_t> w;

                try {
                    cmp_word = ds.Get<bool>();
                } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                if ( cmp_word == true ) {
                    w = libecc_detail::ToWord(op.bn1);
                    if ( w == std::nullopt ) {
                        cmp_word = false;
                    }
                }

                if ( cmp_word == false ) {
                    ret = component::Bignum{ std::to_string(bn[0].Cmp(bn[1])) };
                    goto end;
                } else {
                    int cmp;
                    CF_CHECK_EQ(nn_cmp_word(bn[0].GetPtr(), *w, &cmp), 0);
                    ret = component::Bignum{ std::to_string(cmp) };
                    goto end;
                }
            }
            break;
        case    CF_CALCOP("NegMod(A,B)"):
            CF_CHECK_FALSE(bn[1].IsZero());

            CF_CHECK_EQ(nn_mod_neg(bn.GetResPtr(), bn[0].GetPtr(), bn[1].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("Zero()"):
            CF_NORET(result.SetZero());
            break;
        case    CF_CALCOP("One()"):
            CF_NORET(result.SetOne());
            break;
        case    CF_CALCOP("CondAdd(A,B,C)"):
            CF_CHECK_EQ(nn_cnd_add(
                        !bn[2].IsZero(),
                        bn.GetResPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("CondSub(A,B,C)"):
            CF_CHECK_TRUE(bn[0] > bn[1]);
            CF_CHECK_EQ(nn_cnd_sub(
                        !bn[2].IsZero(),
                        bn.GetResPtr(),
                        bn[0].GetPtr(),
                        bn[1].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        case    CF_CALCOP("RandMod(A)"):
            CF_CHECK_EQ(nn_get_random_mod(
                        bn.GetResPtr(),
                        bn[0].GetPtr()), 0);
            CF_NORET(bn.CopyResult(result));
            break;
        default:
            goto end;
    }

    ret = libecc_detail::To_Component_Bignum(result.GetPtr(), negative);

end:
    libecc_detail::global_ds = nullptr;

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
