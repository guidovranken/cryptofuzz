#include "module.h"
#include <cryptofuzz/util.h>

extern "C" {
    #include <libsig.h>
}

namespace cryptofuzz {
namespace module {
namespace libecc_detail {
    Datasource* global_ds = nullptr;
    FILE* fp_dev_urandom = nullptr;
	const ec_sig_mapping *sm;

    std::map<uint64_t, const ec_str_params*> curveLUT;

    static void AddCurve(const uint64_t curveID, const std::string& curveName) {
        const ec_str_params *curve_params = ec_get_curve_params_by_name((const u8*)curveName.c_str(), curveName.size() + 1);

        CF_ASSERT(curve_params != nullptr, "Cannot initialize curve");

        curveLUT[curveID] = curve_params;
    }

    static const ec_str_params* GetCurve(const component::CurveType& curveType) {
        if ( curveLUT.find(curveType.Get()) == curveLUT.end() ) {
            return nullptr;
        }

        return curveLUT.at(curveType.Get());
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
    CF_ASSERT((libecc_detail::sm = get_sig_by_name("ECDSA")) != nullptr, "Cannot initialize ECDSA");

    /* Load curves */
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool224r1"), "BRAINPOOLP224R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool256r1"), "BRAINPOOLP256R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool384r1"), "BRAINPOOLP384R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("brainpool512r1"), "BRAINPOOLP512R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp192r1"), "SECP192R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp224r1"), "SECP224R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp256r1"), "SECP256R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp384r1"), "SECP384R1");
    libecc_detail::AddCurve(CF_ECC_CURVE("secp521r1"), "SECP521R1");

    /* TODO */
#if 0
    "FRP256V1"
    "GOST256"
    "GOST512"
#endif
}

std::optional<component::ECC_PublicKey> libecc::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    libecc_detail::global_ds = &ds;

    ec_priv_key priv;
	ec_pub_key pub;
    uint8_t* out = nullptr;
	ec_params params;
    ec_sig_alg_type sig_type;
    std::optional<std::vector<uint8_t>> priv_bytes;
    const ec_str_params* curve_params;

    /* Load curve */
    CF_CHECK_NE(curve_params = libecc_detail::GetCurve(op.curveType), nullptr);
    /* noret */ import_params(&params, curve_params);

    sig_type = libecc_detail::sm->type;

    {
        const auto priv_str = op.priv.ToTrimmedString();
        CF_CHECK_NE(priv_str, "0");
        CF_CHECK_NE(priv_bytes = util::DecToBin(priv_str, 96), std::nullopt);
        /* noret */ ec_priv_key_import_from_buf(&priv, &params, priv_bytes->data(), priv_bytes->size(), sig_type);
        memset(&pub, 0, sizeof(pub));
        CF_CHECK_EQ(init_pubkey_from_privkey(&pub, &priv), 0);
        CF_CHECK_EQ(pub.magic, PUB_KEY_MAGIC);

        aff_pt Q_aff;
        prj_pt_to_aff(&Q_aff, &pub.y);
        ec_shortw_aff_to_prj(&pub.y, &Q_aff);
    }
    {
        const size_t outSize = EC_PUB_KEY_EXPORT_SIZE(&pub);
        CF_ASSERT((outSize % 2) == 0, "Public key byte size is not even");
        out = util::malloc(outSize);
        CF_CHECK_EQ(ec_pub_key_export_to_buf(&pub, out, outSize), 0);
        const size_t halfSize = outSize / 2;
        const auto X = util::BinToDec(out, halfSize);
        const auto Y = util::BinToDec(out + halfSize, halfSize);

        ret = {X, Y};
    }

end:
    util::free(out);

    libecc_detail::global_ds = nullptr;
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
