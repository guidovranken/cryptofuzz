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
    const ec_str_params *curve_params;
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
    const char* curveName = "BRAINPOOLP512R1";
    CF_ASSERT((libecc_detail::fp_dev_urandom = fopen("/dev/urandom", "rb")) != NULL, "Failed to open /dev/urandom");
    CF_ASSERT((libecc_detail::sm = get_sig_by_name("ECDSA")) != nullptr, "Cannot initialize ECDSA");
    CF_ASSERT((libecc_detail::curve_params = ec_get_curve_params_by_name((const u8*)curveName, strlen(curveName) + 1)) != nullptr, "Cannot initialize curve");
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

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("brainpool512r1"));
    /* noret */ import_params(&params, libecc_detail::curve_params);
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
