#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include <relic_conf.h>
#include <bls.hpp>

namespace cryptofuzz {
namespace module {

chia_bls::chia_bls(void) :
    Module("chia_bls") {
}

namespace chia_bls_detail {
    component::BLS_PublicKey G1_To_BLS_PublicKey(const bls::G1Element& g1El) {
        g1_t g1;
        g1El.ToNative(&g1);

        char pubstr1[1024];
        char pubstr2[1024];

        fp_write_str(pubstr1, 1024, g1->x, 10);
        fp_write_str(pubstr2, 1024, g1->y, 10);

        return {pubstr1, pubstr2};
    }
}

std::optional<component::BLS_PublicKey> chia_bls::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<component::BLS_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        std::optional<std::vector<uint8_t>> priv_bytes;
        CF_CHECK_NE(priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), bls::PrivateKey::PRIVATE_KEY_SIZE), std::nullopt);
        bls::PrivateKey priv = bls::PrivateKey::FromBytes(priv_bytes->data());
        auto pub = priv.GetG1Element();

        ret = chia_bls_detail::G1_To_BLS_PublicKey(pub);
    } catch ( std::invalid_argument ) { }

end:
    return ret;
}

std::optional<component::BLS_Signature> chia_bls::OpBLS_Sign(operation::BLS_Sign& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<component::BLS_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        std::optional<std::vector<uint8_t>> priv_bytes;
        CF_CHECK_NE(priv_bytes = util::DecToBin(op.priv.ToTrimmedString(), bls::PrivateKey::PRIVATE_KEY_SIZE), std::nullopt);
        bls::PrivateKey priv = bls::PrivateKey::FromBytes(priv_bytes->data());
        /* TODO */
    } catch ( std::invalid_argument ) { }

end:
    return ret;
}

std::optional<bool> chia_bls::OpBLS_Verify(operation::BLS_Verify& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    return {};
}

} /* namespace module */
} /* namespace cryptofuzz */
