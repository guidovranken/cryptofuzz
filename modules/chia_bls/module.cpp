#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>

#include <relic_conf.h>
#include <bls.hpp>

namespace cryptofuzz {
namespace module {

chia_bls::chia_bls(void) :
    Module("Chia Network bls-signatures") {
}

namespace chia_bls_detail {
    class Bignum {
        private:
            bn_st bn;
        public:
            Bignum(void) {
                bn_new(&bn);
                bn_zero(&bn);
            }

            Bignum(bn_st* other) {
                bn_new(&bn);
                bn_zero(&bn);
                bn_copy(&bn, other);
            }

            void SetString(const std::string& s) {
                if ( s.size() > 30 ) {
                    throw std::runtime_error("Integer too large");
                }

                bn_read_str(&bn, s.c_str(), s.size(), 10);
            }

            ~Bignum(void) {
                bn_clean(&bn);
            }

            bn_st* GetPtr(void) {
                return &bn;
            }
    };

    component::BLS_PublicKey G1_To_BLS_PublicKey(g1_t g1) {
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
        chia_bls_detail::Bignum privBn;
        privBn.SetString(op.priv.ToString(ds));

        bls::PrivateKey priv = bls::PrivateKey::FromBN(privBn.GetPtr());
        bls::PublicKey pub = priv.GetPublicKey();

        ret = chia_bls_detail::G1_To_BLS_PublicKey(pub.q);
    } catch ( std::runtime_error ) { }

    return ret;
}

std::optional<component::BLS_Signature> chia_bls::OpBLS_Sign(operation::BLS_Sign& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<component::BLS_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    try {
        chia_bls_detail::Bignum privBn;
        privBn.SetString(op.priv.ToString(ds));
        bls::PrivateKey priv = bls::PrivateKey::FromBN(privBn.GetPtr());
        bls::Signature sig = priv.Sign(op.cleartext.GetPtr(), op.cleartext.GetSize());
    } catch ( std::runtime_error ) { }

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
