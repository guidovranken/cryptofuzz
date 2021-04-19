#include "module.h"
#include <cryptofuzz/util.h>
#include <boost/multiprecision/cpp_int.hpp>

extern "C" {
    #include <uECC.h>
}

namespace cryptofuzz {
namespace module {

micro_ecc::micro_ecc(void) :
    Module("micro-ecc") {
}

namespace micro_ecc_detail {
    static std::optional<uECC_Curve> to_uECC_Curve(const component::CurveType& curveType) {
        switch ( curveType.Get() ) {
            case    CF_ECC_CURVE("secp160r1"):
                return uECC_secp160r1();
            case    CF_ECC_CURVE("secp192r1"):
                return uECC_secp192r1();
            case    CF_ECC_CURVE("secp224r1"):
                return uECC_secp224r1();
            case    CF_ECC_CURVE("secp256r1"):
                return uECC_secp256r1();
            case    CF_ECC_CURVE("secp256k1"):
                return uECC_secp256k1();
            default:
                return std::nullopt;
        }
    }

    static bool EncodeBignum(const std::string s, uint8_t* out, const size_t maxSize) {
        std::vector<uint8_t> v;
        boost::multiprecision::cpp_int c(s);
        boost::multiprecision::export_bits(c, std::back_inserter(v), 8);
        if ( v.size() > maxSize ) {
            return false;
        }
        const auto diff = maxSize - v.size();

        memset(out, 0, maxSize);
        memcpy(out + diff, v.data(), v.size());

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

    component::BignumPair EncodePubkey(const uint8_t* data, const size_t size) {
        if ( (size % 2) != 0 ) {
            abort();
        }
        size_t halfSize = size / 2;

        return {
            micro_ecc_detail::toString(data, halfSize),
            micro_ecc_detail::toString(data + halfSize, halfSize) };
    }
}


std::optional<component::ECC_PublicKey> micro_ecc::OpECC_PrivateToPublic(operation::ECC_PrivateToPublic& op) {
    std::optional<component::ECC_PublicKey> ret = std::nullopt;

    std::optional<uECC_Curve> curve;
    std::vector<uint8_t> priv, pub;

    CF_CHECK_NE(curve = micro_ecc_detail::to_uECC_Curve(op.curveType), std::nullopt);

    priv.resize(uECC_curve_private_key_size(*curve));
    pub.resize(uECC_curve_public_key_size(*curve));

    CF_CHECK_EQ(micro_ecc_detail::EncodeBignum(op.priv.ToTrimmedString(), priv.data(), priv.size()), true);

    CF_CHECK_EQ(uECC_compute_public_key(priv.data(), pub.data(), *curve), 1);

    ret = micro_ecc_detail::EncodePubkey(pub.data(), pub.size());

end:
    return ret;
}

std::optional<bool> micro_ecc::OpECDSA_Verify(operation::ECDSA_Verify& op) {
    std::optional<bool> ret = std::nullopt;

    std::optional<uECC_Curve> curve;
    std::vector<uint8_t> pub, sig;
    size_t pointHalfSize = 0;

    CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("NULL"));
    CF_CHECK_NE(curve = micro_ecc_detail::to_uECC_Curve(op.curveType), std::nullopt);

    pointHalfSize = uECC_curve_public_key_size(*curve) / 2;

    sig.resize(pointHalfSize * 2);
    pub.resize(pointHalfSize * 2);

    CF_CHECK_EQ(micro_ecc_detail::EncodeBignum(op.signature.signature.first.ToTrimmedString(), sig.data(), pointHalfSize), true);
    CF_CHECK_EQ(micro_ecc_detail::EncodeBignum(op.signature.signature.second.ToTrimmedString(), sig.data() + pointHalfSize, pointHalfSize), true);
    CF_CHECK_EQ(micro_ecc_detail::EncodeBignum(op.signature.pub.first.ToTrimmedString(), pub.data(), pointHalfSize), true);
    CF_CHECK_EQ(micro_ecc_detail::EncodeBignum(op.signature.pub.second.ToTrimmedString(), pub.data() + pointHalfSize, pointHalfSize), true);

    ret = uECC_verify(pub.data(), op.cleartext.GetPtr(), op.cleartext.GetSize(), sig.data(), *curve);

end:

    return ret;
}

std::optional<component::ECDSA_Signature> micro_ecc::OpECDSA_Sign(operation::ECDSA_Sign& op) {
    std::optional<component::ECDSA_Signature> ret = std::nullopt;

    std::optional<uECC_Curve> curve;
    std::vector<uint8_t> priv, pub, sig;
    size_t pointHalfSize = 0;

    CF_CHECK_EQ(op.UseRandomNonce(), true);
    CF_CHECK_EQ(op.digestType.Get(), CF_DIGEST("NULL"));
    CF_CHECK_NE(curve = micro_ecc_detail::to_uECC_Curve(op.curveType), std::nullopt);

    priv.resize(uECC_curve_private_key_size(*curve));
    pub.resize(uECC_curve_public_key_size(*curve));

    priv.resize(pointHalfSize);
    pub.resize(pointHalfSize * 2);
    sig.resize(pointHalfSize * 2);

    CF_CHECK_EQ(micro_ecc_detail::EncodeBignum(op.priv.ToTrimmedString(), priv.data(), priv.size()), true);

    CF_CHECK_EQ(uECC_compute_public_key(priv.data(), pub.data(), *curve), 1);

    CF_CHECK_EQ(uECC_sign(priv.data(), op.cleartext.GetPtr(), op.cleartext.GetSize(), sig.data(), *curve), 1);

    ret = {
            {micro_ecc_detail::toString(sig.data(), pointHalfSize), micro_ecc_detail::toString(sig.data() + pointHalfSize, pointHalfSize) },
            micro_ecc_detail::EncodePubkey(pub.data(), pub.size()) };
end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
