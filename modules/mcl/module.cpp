#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include <fuzzing/datasource/id.hpp>
//#include <mcl/ec.hpp>
//#include <mcl/ecdsa.hpp>

#if 0
#include <mcl/bn256.hpp>
#undef MCL_MAX_FR_BIT_SIZE
#undef MCL_MAX_FP_BIT_SIZE

#include <mcl/bn384.hpp>
#undef MCL_MAX_FR_BIT_SIZE
#undef MCL_MAX_FP_BIT_SIZE

#include <mcl/bn512.hpp>
#undef MCL_MAX_FR_BIT_SIZE
#undef MCL_MAX_FP_BIT_SIZE
#endif

#include <mcl/bls12_381.hpp>
//#undef MCL_MAX_FR_BIT_SIZE
//#undef MCL_MAX_FP_BIT_SIZE

#include <iostream>
#include <vector>
#include <string>
#include <sstream>

namespace cryptofuzz {
namespace module {

mcl::mcl(void) :
    Module("mcl") {
        /*
        bool b;
        ::mcl::ecdsa::init(&b);
        if ( !b ) abort();
        */

        //::mcl::bls12::initPairing();
        ::mcl::bn::initPairing(::mcl::BLS12_381);
        /*
        ::mcl::bn256::initPairing();
        ::mcl::bn384::initPairing();
        ::mcl::bn512::initPairing();
        */
}

namespace mcl_detail {

std::vector<std::string> splitPubkeyStr(const std::string& s) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string tok;

    while (getline(ss, tok, ' ') ) {
        parts.push_back(tok);
    }

    return parts;
}

/*
namespace bn256 {
    using namespace ::mcl::bn256;
#include "mclpairing.h"
}

namespace bn384 {
    using namespace ::mcl::bn384;
#include "mclpairing.h"
}

namespace bn512 {
    using namespace ::mcl::bn512;
#include "mclpairing.h"
}
*/
namespace bls12  {
    using namespace ::mcl::bls12;
#include "mclpairing.h"
}

}

#if 0
std::optional<component::ECC_PublicKey> mcl::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    try {
        ::mcl::ecdsa::SecretKey sec;
        sec.setStr(op.priv.ToString(ds).c_str(), 10);
        ::mcl::ecdsa::PublicKey pub;
        ::mcl::ecdsa::getPublicKey(pub, sec);
        pub.normalize();
        const auto parts = mcl_detail::splitPubkeyStr(pub.getStr(10));
        if ( parts.size() != 3 ) {
            abort();
        }
        ret = { parts[1], parts[2] };
    } catch ( cybozu::Exception ) { }

end:
    return ret;
}

std::optional<component::ECDSA_Signature> mcl::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    try {
        ::mcl::ecdsa::Signature sig;
        ::mcl::ecdsa::SecretKey sec;
        sec.setStr(op.priv.ToString(ds).c_str(), 10);
        sign(sig, sec, op.cleartext.GetPtr(), op.cleartext.GetSize());
        const auto parts = mcl_detail::splitPubkeyStr(sig.getStr(10));
        if ( parts.size() != 2 ) {
            abort();
        }
        /* Cannot return signature because nonce is randomized, and this will give
         * different results each time
         *
         * ret = { parts[0], parts[1] };
        */
    } catch ( cybozu::Exception ) { }

end:
    return ret;
}

std::optional<bool> mcl::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    CF_CHECK_EQ(op.curveType.Get(), CF_ECC_CURVE("secp256k1"));

    {
        ::mcl::ecdsa::Signature sig;
        ::mcl::ecdsa::PublicKey pub;

        try {
            sig.r.setStr(op.signature.first.ToString(ds), 10);
            sig.s.setStr(op.signature.second.ToString(ds), 10);

            pub = ::mcl::ecdsa::PublicKey(
                    ::mcl::ecdsa::Fp(op.pub.first.ToString(ds).c_str(), 10),
                    ::mcl::ecdsa::Fp(op.pub.second.ToString(ds).c_str(), 10));
        } catch ( cybozu::Exception ) {
            return ret;
        }

        ret = verify(sig, pub, op.cleartext.GetPtr(), op.cleartext.GetSize());
    }

end:
    return ret;
}
#endif

std::optional<component::BLS_PublicKey> mcl::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    switch ( op.curveType.Get() ) {
        case    CF_ECC_CURVE("BLS12_381"):
            return mcl_detail::bls12::OpBLS_PrivateToPublic(op);
            /*
        case    CF_ECC_CURVE("BN256"):
            return mcl_detail::bn256::OpBLS_PrivateToPublic(op);
        case    CF_ECC_CURVE("BN384"):
            return mcl_detail::bn384::OpBLS_PrivateToPublic(op);
        case    CF_ECC_CURVE("BN512"):
            return mcl_detail::bn512::OpBLS_PrivateToPublic(op);
            */
        default:
            return std::nullopt;
    }
}

std::optional<component::BLS_Signature> mcl::OpBLS_Sign(operation::BLS_Sign& op) {
    switch ( op.curveType.Get() ) {
        case    CF_ECC_CURVE("BLS12_381"):
            return mcl_detail::bls12::OpBLS_Sign(op);
            /*
        case    CF_ECC_CURVE("BN256"):
            return mcl_detail::bn256::OpBLS_Sign(op);
        case    CF_ECC_CURVE("BN384"):
            return mcl_detail::bn384::OpBLS_Sign(op);
        case    CF_ECC_CURVE("BN512"):
            return mcl_detail::bn512::OpBLS_Sign(op);
            */
        default:
            return std::nullopt;
    }
}

std::optional<bool> mcl::OpBLS_Verify(operation::BLS_Verify& op) {
    switch ( op.curveType.Get() ) {
        case    CF_ECC_CURVE("BLS12_381"):
            return mcl_detail::bls12::OpBLS_Verify(op);
            /*
        case    CF_ECC_CURVE("BN256"):
            return mcl_detail::bn256::OpBLS_Verify(op);
        case    CF_ECC_CURVE("BN384"):
            return mcl_detail::bn384::OpBLS_Verify(op);
        case    CF_ECC_CURVE("BN512"):
            return mcl_detail::bn512::OpBLS_Verify(op);
            */
        default:
            return std::nullopt;
    }

    return std::nullopt;
}

} /* namespace module */
} /* namespace cryptofuzz */
