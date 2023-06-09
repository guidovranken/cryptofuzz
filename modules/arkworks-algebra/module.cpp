#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int arkworks_algebra_bignumcalc(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
    int arkworks_algebra_bignumcalc_bn254_fq(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
    int arkworks_algebra_bignumcalc_bn254_fr(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
    int arkworks_algebra_bignumcalc_bls12_381_fr(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
    int arkworks_algebra_bignumcalc_bls12_381_fq(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
    int arkworks_algebra_g1_isoncurve_bn254(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes);
    int arkworks_algebra_g1_privatetopublic_bn254(
            uint64_t* priv_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_add_bn254(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* bx_bytes,
            uint64_t* by_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_mul_bn254(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* b_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_neg_bn254(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_batchverify_bn254(
            uint64_t* in_data,
            uint64_t num_elements);
    int arkworks_algebra_g1_isoncurve_bls12_381(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes);
    int arkworks_algebra_g1_privatetopublic_bls12_381(
            uint64_t* priv_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_add_bls12_381(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* bx_bytes,
            uint64_t* by_bytes,
            int affine,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_mul_bls12_381(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* b_bytes,
            int affine,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_neg_bls12_381(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            int affine,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g2_isoncurve_bls12_381(
            uint64_t* av_bytes,
            uint64_t* aw_bytes,
            uint64_t* ax_bytes,
            uint64_t* ay_bytes);
    int arkworks_algebra_g2_add_bls12_381(
            uint64_t* av_bytes,
            uint64_t* aw_bytes,
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* bv_bytes,
            uint64_t* bw_bytes,
            uint64_t* bx_bytes,
            uint64_t* by_bytes,
            int affine,
            uint64_t* result_v,
            uint64_t* result_w,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g2_mul_bls12_381(
            uint64_t* av_bytes,
            uint64_t* aw_bytes,
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* b_bytes,
            int affine,
            uint64_t* result_v,
            uint64_t* result_w,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g2_neg_bls12_381(
            uint64_t* av_bytes,
            uint64_t* aw_bytes,
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            int affine,
            uint64_t* result_v,
            uint64_t* result_w,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_multiexp_bls12_381(
            uint64_t* x,
            uint64_t* y,
            uint64_t* scalars,
            uint64_t num,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_isoncurve_bls12_377(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes);
    int arkworks_algebra_g1_privatetopublic_bls12_377(
            uint64_t* priv_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_add_bls12_377(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* bx_bytes,
            uint64_t* by_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_mul_bls12_377(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* b_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g1_neg_bls12_377(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_g2_mul_bls12_377(
            uint64_t* av_bytes,
            uint64_t* aw_bytes,
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* b_bytes,
            int affine,
            uint64_t* result_v,
            uint64_t* result_w,
            uint64_t* result_x,
            uint64_t* result_y);
    int arkworks_algebra_bignumcalc_bls12_377_fq(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
    int arkworks_algebra_bignumcalc_bls12_377_fr(
            uint64_t op,
            uint64_t* bn0_bytes,
            uint64_t* bn1_bytes,
            uint64_t* bn2_bytes,
            uint64_t* result);
}

namespace cryptofuzz {
namespace module {

arkworks_algebra::arkworks_algebra(void) :
    Module("arkworks-algebra") { }

namespace arkworks_algebra_detail {
    std::optional<std::array<uint64_t, 4>> To4U64(const component::Bignum& bn) {
        std::optional<std::array<uint64_t, 4>> ret = std::nullopt;

        const auto bin = util::DecToBin(bn.ToTrimmedString(), 32);
        CF_CHECK_NE(bin, std::nullopt);

        std::array<uint64_t, 4> arr;
        memcpy(&arr[0], bin->data(), sizeof(uint64_t));
        arr[0] = __bswap_64(arr[0]);
        memcpy(&arr[1], bin->data() + 8, sizeof(uint64_t));
        arr[1] = __bswap_64(arr[1]);
        memcpy(&arr[2], bin->data() + 16, sizeof(uint64_t));
        arr[2] = __bswap_64(arr[2]);
        memcpy(&arr[3], bin->data() + 24, sizeof(uint64_t));
        arr[3] = __bswap_64(arr[3]);

        std::reverse(arr.begin(), arr.end());
        ret = arr;
end:
        return ret;
    }
    std::optional<std::array<uint64_t, 6>> To6U64(const component::Bignum& bn) {
        std::optional<std::array<uint64_t, 6>> ret = std::nullopt;

        const auto bin = util::DecToBin(bn.ToTrimmedString(), 48);
        CF_CHECK_NE(bin, std::nullopt);

        std::array<uint64_t, 6> arr;
        memcpy(&arr[0], bin->data(), sizeof(uint64_t));
        arr[0] = __bswap_64(arr[0]);
        memcpy(&arr[1], bin->data() + 8, sizeof(uint64_t));
        arr[1] = __bswap_64(arr[1]);
        memcpy(&arr[2], bin->data() + 16, sizeof(uint64_t));
        arr[2] = __bswap_64(arr[2]);
        memcpy(&arr[3], bin->data() + 24, sizeof(uint64_t));
        arr[3] = __bswap_64(arr[3]);
        memcpy(&arr[4], bin->data() + 32, sizeof(uint64_t));
        arr[4] = __bswap_64(arr[4]);
        memcpy(&arr[5], bin->data() + 40, sizeof(uint64_t));
        arr[5] = __bswap_64(arr[5]);

        std::reverse(arr.begin(), arr.end());
        ret = arr;
end:
        return ret;
    }
    const component::Bignum From4U64(std::array<uint64_t, 4> u64) {
        std::reverse(u64.begin(), u64.end());
        std::vector<uint8_t> bin(32);
        u64[0] = __bswap_64(u64[0]);
        u64[1] = __bswap_64(u64[1]);
        u64[2] = __bswap_64(u64[2]);
        u64[3] = __bswap_64(u64[3]);
        memcpy(bin.data(), &u64[0], sizeof(uint64_t));
        memcpy(bin.data() + 8, &u64[1], sizeof(uint64_t));
        memcpy(bin.data() + 16, &u64[2], sizeof(uint64_t));
        memcpy(bin.data() + 24, &u64[3], sizeof(uint64_t));
        return component::Bignum{util::BinToDec(bin)};
    }
    const component::Bignum From6U64(std::array<uint64_t, 6> u64) {
        std::reverse(u64.begin(), u64.end());
        std::vector<uint8_t> bin(48);
        u64[0] = __bswap_64(u64[0]);
        u64[1] = __bswap_64(u64[1]);
        u64[2] = __bswap_64(u64[2]);
        u64[3] = __bswap_64(u64[3]);
        u64[4] = __bswap_64(u64[4]);
        u64[5] = __bswap_64(u64[5]);
        memcpy(bin.data(), &u64[0], sizeof(uint64_t));
        memcpy(bin.data() + 8, &u64[1], sizeof(uint64_t));
        memcpy(bin.data() + 16, &u64[2], sizeof(uint64_t));
        memcpy(bin.data() + 24, &u64[3], sizeof(uint64_t));
        memcpy(bin.data() + 32, &u64[4], sizeof(uint64_t));
        memcpy(bin.data() + 40, &u64[5], sizeof(uint64_t));
        return component::Bignum{util::BinToDec(bin)};
    }

    component::G1 ToG1(
            const std::array<uint64_t, 4>& result_x,
            const std::array<uint64_t, 4>& result_y) {
        const auto x = arkworks_algebra_detail::From4U64(result_x).ToTrimmedString();
        auto y = arkworks_algebra_detail::From4U64(result_y).ToTrimmedString();
        if (x == "0" && y == "1") {
            y = "0";
        }

        return component::G1{x, y};
    }
    component::G1 ToG1(
            const std::array<uint64_t, 6>& result_x,
            const std::array<uint64_t, 6>& result_y) {
        const auto x = arkworks_algebra_detail::From6U64(result_x).ToTrimmedString();
        auto y = arkworks_algebra_detail::From6U64(result_y).ToTrimmedString();
        if (x == "0" && y == "1") {
            y = "0";
        }

        return component::G1{x, y};
    }
    component::G2 ToG2(
            const std::array<uint64_t, 6>& result_v,
            const std::array<uint64_t, 6>& result_w,
            const std::array<uint64_t, 6>& result_x,
            const std::array<uint64_t, 6>& result_y) {
        const auto v = arkworks_algebra_detail::From6U64(result_v).ToTrimmedString();
        auto w = arkworks_algebra_detail::From6U64(result_w).ToTrimmedString();
        const auto x = arkworks_algebra_detail::From6U64(result_x).ToTrimmedString();
        const auto y = arkworks_algebra_detail::From6U64(result_y).ToTrimmedString();

        if (v == "0" && w == "1" && x == "0" && y == "0") {
            w = "0";
        }

        return component::G2{v, w, x, y};
    }
}

std::optional<component::BLS_PublicKey> arkworks_algebra::OpBLS_PrivateToPublic(operation::BLS_PrivateToPublic& op) {
    if (
        op.curveType.Get() != CF_ECC_CURVE("alt_bn128") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_381") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_377") ) {
        return std::nullopt;
    }

    std::optional<component::BLS_PublicKey> ret = std::nullopt;

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        std::optional<std::array<uint64_t, 4>> priv;
        std::array<uint64_t, 4> result_x, result_y;

        CF_CHECK_NE(priv = arkworks_algebra_detail::To4U64(op.priv), std::nullopt);

        CF_CHECK_NE(arkworks_algebra_g1_privatetopublic_bn254(
                    priv->data(),
                    result_x.data(),
                    result_y.data()
                    ), -1);

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ||
                op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
        std::optional<std::array<uint64_t, 4>> priv;
        std::array<uint64_t, 6> result_x, result_y;

        CF_CHECK_NE(priv = arkworks_algebra_detail::To4U64(op.priv), std::nullopt);

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            CF_CHECK_NE(arkworks_algebra_g1_privatetopublic_bls12_381(
                        priv->data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
            CF_CHECK_NE(arkworks_algebra_g1_privatetopublic_bls12_377(
                        priv->data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else {
            CF_UNREACHABLE();
        }

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else {
        CF_UNREACHABLE();
    }

end:
    return ret;
}

std::optional<bool> arkworks_algebra::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    if (
        op.curveType.Get() != CF_ECC_CURVE("alt_bn128") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_381") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_377") ) {
        return std::nullopt;
    }

    std::optional<bool> ret = std::nullopt;

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        std::optional<std::array<uint64_t, 4>> ax, ay;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To4U64(op.g1.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To4U64(op.g1.second), std::nullopt);

        const auto r = arkworks_algebra_g1_isoncurve_bn254(
                    ax->data(),
                    ay->data());
        CF_CHECK_NE(r, -1);
        ret = r == 1;
    } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ||
                op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
        std::optional<std::array<uint64_t, 6>> ax, ay;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.g1.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.g1.second), std::nullopt);

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            const auto r = arkworks_algebra_g1_isoncurve_bls12_381(
                        ax->data(),
                        ay->data());
            CF_CHECK_NE(r, -1);
            ret = r == 1;
        } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
            const auto r = arkworks_algebra_g1_isoncurve_bls12_377(
                        ax->data(),
                        ay->data());
            CF_CHECK_NE(r, -1);
            ret = r == 1;
        } else {
            CF_UNREACHABLE();
        }
    } else {
        CF_UNREACHABLE();
    }

end:
    return ret;
}

std::optional<component::G1> arkworks_algebra::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    if (
        op.curveType.Get() != CF_ECC_CURVE("alt_bn128") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_381") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_377") ) {
        return std::nullopt;
    }

    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        std::optional<std::array<uint64_t, 4>> ax, ay, bx, by;
        std::array<uint64_t, 4> result_x, result_y;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To4U64(op.a.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To4U64(op.a.second), std::nullopt);
        CF_CHECK_NE(bx = arkworks_algebra_detail::To4U64(op.b.first), std::nullopt);
        CF_CHECK_NE(by = arkworks_algebra_detail::To4U64(op.b.second), std::nullopt);

        CF_CHECK_NE(arkworks_algebra_g1_add_bn254(
                    ax->data(),
                    ay->data(),
                    bx->data(),
                    by->data(),
                    result_x.data(),
                    result_y.data()
                    ), -1);

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ||
                op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
        std::optional<std::array<uint64_t, 6>> ax, ay, bx, by;
        std::array<uint64_t, 6> result_x, result_y;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.a.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.a.second), std::nullopt);
        CF_CHECK_NE(bx = arkworks_algebra_detail::To6U64(op.b.first), std::nullopt);
        CF_CHECK_NE(by = arkworks_algebra_detail::To6U64(op.b.second), std::nullopt);

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            bool affine = true;
            try {
                affine = ds.Get<bool>();
            } catch ( fuzzing::datasource::Base::OutOfData ) {
            }

            CF_CHECK_NE(arkworks_algebra_g1_add_bls12_381(
                        ax->data(),
                        ay->data(),
                        bx->data(),
                        by->data(),
                        affine,
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
            CF_CHECK_NE(arkworks_algebra_g1_add_bls12_377(
                        ax->data(),
                        ay->data(),
                        bx->data(),
                        by->data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else {
            CF_UNREACHABLE();
        }

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else {
        CF_UNREACHABLE();
    }

end:
    return ret;
}

std::optional<component::G1> arkworks_algebra::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    if (
        op.curveType.Get() != CF_ECC_CURVE("alt_bn128") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_381") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_377") ) {
        return std::nullopt;
    }

    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        std::optional<std::array<uint64_t, 4>> ax, ay, b;
        std::array<uint64_t, 4> result_x, result_y;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To4U64(op.a.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To4U64(op.a.second), std::nullopt);
        CF_CHECK_NE(b = arkworks_algebra_detail::To4U64(op.b), std::nullopt);

        CF_CHECK_NE(arkworks_algebra_g1_mul_bn254(
                    ax->data(),
                    ay->data(),
                    b->data(),
                    result_x.data(),
                    result_y.data()
                    ), -1);

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ||
                op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
        std::optional<std::array<uint64_t, 6>> ax, ay;
        std::optional<std::array<uint64_t, 4>> b;
        std::array<uint64_t, 6> result_x, result_y;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.a.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.a.second), std::nullopt);
        CF_CHECK_NE(b = arkworks_algebra_detail::To4U64(op.b), std::nullopt);

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            bool affine = true;
            try {
                affine = ds.Get<bool>();
            } catch ( fuzzing::datasource::Base::OutOfData ) {
            }

            CF_CHECK_NE(arkworks_algebra_g1_mul_bls12_381(
                        ax->data(),
                        ay->data(),
                        b->data(),
                        affine,
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
            CF_CHECK_NE(arkworks_algebra_g1_mul_bls12_377(
                        ax->data(),
                        ay->data(),
                        b->data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else {
            CF_UNREACHABLE();
        }

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else {
        CF_UNREACHABLE();
    }

end:
    return ret;
}

std::optional<component::G1> arkworks_algebra::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    if (
        op.curveType.Get() != CF_ECC_CURVE("alt_bn128") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_381") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_377") ) {
        return std::nullopt;
    }

    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.curveType.Get() == CF_ECC_CURVE("alt_bn128") ) {
        std::optional<std::array<uint64_t, 4>> ax, ay;
        std::array<uint64_t, 4> result_x, result_y;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To4U64(op.a.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To4U64(op.a.second), std::nullopt);

        CF_CHECK_NE(arkworks_algebra_g1_neg_bn254(
                    ax->data(),
                    ay->data(),
                    result_x.data(),
                    result_y.data()
                    ), -1);

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ||
                op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
        std::optional<std::array<uint64_t, 6>> ax, ay;
        std::array<uint64_t, 6> result_x, result_y;

        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.a.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.a.second), std::nullopt);

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            bool affine = true;
            try {
                affine = ds.Get<bool>();
            } catch ( fuzzing::datasource::Base::OutOfData ) {
            }

            CF_CHECK_NE(arkworks_algebra_g1_neg_bls12_381(
                        ax->data(),
                        ay->data(),
                        affine,
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
            CF_CHECK_NE(arkworks_algebra_g1_neg_bls12_377(
                        ax->data(),
                        ay->data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
        } else {
            CF_UNREACHABLE();
        }

        ret = arkworks_algebra_detail::ToG1(result_x, result_y);
    } else {
        CF_UNREACHABLE();
    }

end:
    return ret;
}

std::optional<bool> arkworks_algebra::OpBLS_IsG2OnCurve(operation::BLS_IsG2OnCurve& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<bool> ret = std::nullopt;

    {
        std::optional<std::array<uint64_t, 6>> av, aw, ax, ay;

        CF_CHECK_NE(av = arkworks_algebra_detail::To6U64(op.g2.first.first), std::nullopt);
        CF_CHECK_NE(aw = arkworks_algebra_detail::To6U64(op.g2.first.second), std::nullopt);
        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.g2.second.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.g2.second.second), std::nullopt);

        const auto r = arkworks_algebra_g2_isoncurve_bls12_381(
                av->data(),
                aw->data(),
                ax->data(),
                ay->data());
        CF_CHECK_NE(r, -1);
        ret = r == 1;
    }

end:
    return ret;
}

std::optional<component::G2> arkworks_algebra::OpBLS_G2_Add(operation::BLS_G2_Add& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    {
        std::optional<std::array<uint64_t, 6>> av, aw, ax, ay;
        std::optional<std::array<uint64_t, 6>> bv, bw, bx, by;
        std::array<uint64_t, 6> result_v, result_w, result_x, result_y;

        CF_CHECK_NE(av = arkworks_algebra_detail::To6U64(op.a.first.first), std::nullopt);
        CF_CHECK_NE(aw = arkworks_algebra_detail::To6U64(op.a.first.second), std::nullopt);
        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.a.second.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.a.second.second), std::nullopt);

        CF_CHECK_NE(bv = arkworks_algebra_detail::To6U64(op.b.first.first), std::nullopt);
        CF_CHECK_NE(bw = arkworks_algebra_detail::To6U64(op.b.first.second), std::nullopt);
        CF_CHECK_NE(bx = arkworks_algebra_detail::To6U64(op.b.second.first), std::nullopt);
        CF_CHECK_NE(by = arkworks_algebra_detail::To6U64(op.b.second.second), std::nullopt);

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            bool affine = true;
            try {
                affine = ds.Get<bool>();
            } catch ( fuzzing::datasource::Base::OutOfData ) {
            }

            CF_CHECK_NE(arkworks_algebra_g2_add_bls12_381(
                        av->data(),
                        aw->data(),
                        ax->data(),
                        ay->data(),
                        bv->data(),
                        bw->data(),
                        bx->data(),
                        by->data(),
                        affine,
                        result_v.data(),
                        result_w.data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
        ret = arkworks_algebra_detail::ToG2(result_v, result_w, result_x, result_y);
        }
    }
end:
    return ret;
}

std::optional<component::G2> arkworks_algebra::OpBLS_G2_Mul(operation::BLS_G2_Mul& op) {
    if (
        op.curveType.Get() != CF_ECC_CURVE("BLS12_381") &&
        op.curveType.Get() != CF_ECC_CURVE("BLS12_377") ) {
        return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    {
        std::optional<std::array<uint64_t, 6>> av, aw, ax, ay;
        std::optional<std::array<uint64_t, 4>> b;
        std::array<uint64_t, 6> result_v, result_w, result_x, result_y;

        CF_CHECK_NE(av = arkworks_algebra_detail::To6U64(op.a.first.first), std::nullopt);
        CF_CHECK_NE(aw = arkworks_algebra_detail::To6U64(op.a.first.second), std::nullopt);
        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.a.second.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.a.second.second), std::nullopt);
        CF_CHECK_NE(b = arkworks_algebra_detail::To4U64(op.b), std::nullopt);

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            bool affine = true;
            try {
                affine = ds.Get<bool>();
            } catch ( fuzzing::datasource::Base::OutOfData ) {
            }

            CF_CHECK_NE(arkworks_algebra_g2_mul_bls12_381(
                        av->data(),
                        aw->data(),
                        ax->data(),
                        ay->data(),
                        b->data(),
                        affine,
                        result_v.data(),
                        result_w.data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
            ret = arkworks_algebra_detail::ToG2(result_v, result_w, result_x, result_y);
        } else if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_377") ) {
            bool affine = true;
            try {
                affine = ds.Get<bool>();
            } catch ( fuzzing::datasource::Base::OutOfData ) {
            }

            CF_CHECK_NE(arkworks_algebra_g2_mul_bls12_377(
                        av->data(),
                        aw->data(),
                        ax->data(),
                        ay->data(),
                        b->data(),
                        affine,
                        result_v.data(),
                        result_w.data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
            ret = arkworks_algebra_detail::ToG2(result_v, result_w, result_x, result_y);
        }
    }
end:
    return ret;
}

std::optional<component::G2> arkworks_algebra::OpBLS_G2_Neg(operation::BLS_G2_Neg& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<component::G2> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    {
        std::optional<std::array<uint64_t, 6>> av, aw, ax, ay;
        std::array<uint64_t, 6> result_v, result_w, result_x, result_y;

        CF_CHECK_NE(av = arkworks_algebra_detail::To6U64(op.a.first.first), std::nullopt);
        CF_CHECK_NE(aw = arkworks_algebra_detail::To6U64(op.a.first.second), std::nullopt);
        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(op.a.second.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(op.a.second.second), std::nullopt);

        bool affine = true;
        try {
            affine = ds.Get<bool>();
        } catch ( fuzzing::datasource::Base::OutOfData ) {
        }

        if ( op.curveType.Get() == CF_ECC_CURVE("BLS12_381") ) {
            CF_CHECK_NE(arkworks_algebra_g2_neg_bls12_381(
                        av->data(),
                        aw->data(),
                        ax->data(),
                        ay->data(),
                        affine,
                        result_v.data(),
                        result_w.data(),
                        result_x.data(),
                        result_y.data()
                        ), -1);
        ret = arkworks_algebra_detail::ToG2(result_v, result_w, result_x, result_y);
        }
    }
end:
    return ret;
}

std::optional<bool> arkworks_algebra::OpBLS_BatchVerify(operation::BLS_BatchVerify& op) {
    std::optional<bool> ret = std::nullopt;

    std::vector<uint64_t> data;

    for (const auto& cur : op.bf.c) {
        std::optional<std::array<uint64_t, 4>> el;

        CF_CHECK_NE(el = arkworks_algebra_detail::To4U64(cur.g1.first), std::nullopt);
        data.insert(data.end(), el->begin(), el->end());

        CF_CHECK_NE(el = arkworks_algebra_detail::To4U64(cur.g1.second), std::nullopt);
        data.insert(data.end(), el->begin(), el->end());

        CF_CHECK_NE(el = arkworks_algebra_detail::To4U64(cur.g2.first.first), std::nullopt);
        data.insert(data.end(), el->begin(), el->end());

        CF_CHECK_NE(el = arkworks_algebra_detail::To4U64(cur.g2.first.second), std::nullopt);
        data.insert(data.end(), el->begin(), el->end());

        CF_CHECK_NE(el = arkworks_algebra_detail::To4U64(cur.g2.second.first), std::nullopt);
        data.insert(data.end(), el->begin(), el->end());

        CF_CHECK_NE(el = arkworks_algebra_detail::To4U64(cur.g2.second.second), std::nullopt);
        data.insert(data.end(), el->begin(), el->end());
    }

    arkworks_algebra_batchverify_bn254(data.data(), op.bf.c.size());
end:
    return ret;
}

std::optional<component::G1> arkworks_algebra::OpBLS_G1_MultiExp(operation::BLS_G1_MultiExp& op) {
    if ( op.curveType.Get() != CF_ECC_CURVE("BLS12_381") ) {
        return std::nullopt;
    }

    std::optional<component::G1> ret = std::nullopt;

    const size_t num = op.points_scalars.points_scalars.size();

    std::vector<uint64_t> x, y, scalars;

    for (size_t i = 0; i < num; i++) {
        std::optional<std::array<uint64_t, 6>> ax, ay;
        std::optional<std::array<uint64_t, 4>> b;

        const auto& cur = op.points_scalars.points_scalars[i];
        CF_CHECK_NE(ax = arkworks_algebra_detail::To6U64(cur.first.first), std::nullopt);
        CF_CHECK_NE(ay = arkworks_algebra_detail::To6U64(cur.first.second), std::nullopt);

        /* Workaround for https://github.com/arkworks-rs/algebra/issues/656 */
        CF_CHECK_TRUE(cur.second.IsLessThan("52435875175126190479447740508185965837690552500527637822603658699938581184513"));

        CF_CHECK_NE(b = arkworks_algebra_detail::To4U64(cur.second), std::nullopt);

        for (const auto v : *ax) {
            x.push_back(v);
        }
        for (const auto v : *ay) {
            y.push_back(v);
        }
        for (const auto v : *b) {
            scalars.push_back(v);
        }
    }

    std::array<uint64_t, 6> result_x, result_y;
    CF_CHECK_EQ(arkworks_algebra_g1_multiexp_bls12_381(
                x.data(),
                y.data(),
                scalars.data(),
                num,
                result_x.data(),
                result_y.data()), 0);

    ret = arkworks_algebra_detail::ToG1(result_x, result_y);

end:
    return ret;
}

std::optional<component::Bignum> arkworks_algebra::OpBignumCalc(operation::BignumCalc& op) {
    if ( op.modulo == std::nullopt ) {
        return std::nullopt;
    }

    uint8_t mod = 0;
    if ( op.modulo->ToTrimmedString() ==
            "115792089237316195423570985008687907853269984665640564039457584007913129639936" ) {
        mod = 1;
    } else if ( op.modulo->ToTrimmedString() ==
            "21888242871839275222246405745257275088696311157297823662689037894645226208583" ) {
        mod = 2;
    } else if ( op.modulo->ToTrimmedString() ==
            "21888242871839275222246405745257275088548364400416034343698204186575808495617" ) {
        mod = 3;
    } else if ( op.modulo->ToTrimmedString() ==
            "52435875175126190479447740508185965837690552500527637822603658699938581184513" ) {
        mod = 4;
    } else if ( op.modulo->ToTrimmedString() ==
            "8444461749428370424248824938781546531375899335154063827935233455917409239041" ) {
        mod = 5;
    } else if ( op.modulo->ToTrimmedString() ==
            "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177" ) {
        mod = 6;
    } else if ( op.modulo->ToTrimmedString() ==
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787" ) {
        mod = 7;
    } else {
        return std::nullopt;
    }

    std::optional<component::Bignum> ret = std::nullopt;

    std::optional<std::array<uint64_t, 4>> bn0, bn1, bn2;
    std::optional<std::array<uint64_t, 6>> bn0_6, bn1_6, bn2_6;
    std::array<uint64_t, 4> result;
    std::array<uint64_t, 6> result_6;
    if (mod != 6 && mod != 7) {
        CF_CHECK_NE(bn0 = arkworks_algebra_detail::To4U64(op.bn0), std::nullopt);
        CF_CHECK_NE(bn1 = arkworks_algebra_detail::To4U64(op.bn1), std::nullopt);
        CF_CHECK_NE(bn2 = arkworks_algebra_detail::To4U64(op.bn2), std::nullopt);
    } else {
        CF_CHECK_NE(bn0_6 = arkworks_algebra_detail::To6U64(op.bn0), std::nullopt);
        CF_CHECK_NE(bn1_6 = arkworks_algebra_detail::To6U64(op.bn1), std::nullopt);
        CF_CHECK_NE(bn2_6 = arkworks_algebra_detail::To6U64(op.bn2), std::nullopt);
    }

    static const std::map<uint64_t, uint64_t> LUT = {
        { CF_CALCOP("Add(A,B)"), 0 },
        { CF_CALCOP("Sub(A,B)"), 1 },
        { CF_CALCOP("LShift1(A)"), 2 },
        { CF_CALCOP("LShift(A)"), 3 },
        { CF_CALCOP("RShift(A,B)"), 4 },
        { CF_CALCOP("InvMod(A,B)"), 5 },
        { CF_CALCOP("Sqr(A)"), 6 },
        { CF_CALCOP("Sqrt(A)"), 7 },
        { CF_CALCOP("Mul(A,B)"), 8 },
        { CF_CALCOP("Neg(A)"), 9 },
    };

    CF_CHECK_TRUE(LUT.find(op.calcOp.Get()) != LUT.end());

    {
        int res;
        switch ( mod ) {
            case    1:
                res = arkworks_algebra_bignumcalc(
                        LUT.at(op.calcOp.Get()),
                        bn0->data(),
                        bn1->data(),
                        bn2->data(),
                        result.data()
                );
                break;
            case    2:
                res = arkworks_algebra_bignumcalc_bn254_fq(
                        LUT.at(op.calcOp.Get()),
                        bn0->data(),
                        bn1->data(),
                        bn2->data(),
                        result.data()
                );
                break;
            case    3:
                res = arkworks_algebra_bignumcalc_bn254_fr(
                        LUT.at(op.calcOp.Get()),
                        bn0->data(),
                        bn1->data(),
                        bn2->data(),
                        result.data()
                );
                break;
            case    4:
                res = arkworks_algebra_bignumcalc_bls12_381_fr(
                        LUT.at(op.calcOp.Get()),
                        bn0->data(),
                        bn1->data(),
                        bn2->data(),
                        result.data()
                );
                break;
            case    5:
                res = arkworks_algebra_bignumcalc_bls12_377_fr(
                        LUT.at(op.calcOp.Get()),
                        bn0->data(),
                        bn1->data(),
                        bn2->data(),
                        result.data()
                );
                break;
            case    6:
                res = arkworks_algebra_bignumcalc_bls12_377_fq(
                        LUT.at(op.calcOp.Get()),
                        bn0_6->data(),
                        bn1_6->data(),
                        bn2_6->data(),
                        result_6.data()
                );
                break;
            case    7:
                res = arkworks_algebra_bignumcalc_bls12_381_fq(
                        LUT.at(op.calcOp.Get()),
                        bn0_6->data(),
                        bn1_6->data(),
                        bn2_6->data(),
                        result_6.data()
                );
                break;
            default:
                CF_UNREACHABLE();
        }

        CF_CHECK_NE(res, -1);

        if (mod != 6 && mod != 7) {
            ret = arkworks_algebra_detail::From4U64(result);
        } else {
            ret = arkworks_algebra_detail::From6U64(result_6);
        }
    }

end:
    return ret;
}

bool arkworks_algebra::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
