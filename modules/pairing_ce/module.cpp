#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>

extern "C" {
    int pairing_ce_g1_isoncurve(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes);
    int pairing_ce_g1_add(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* bx_bytes,
            uint64_t* by_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int pairing_ce_g1_mul(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* b_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
    int pairing_ce_g1_neg(
            uint64_t* ax_bytes,
            uint64_t* ay_bytes,
            uint64_t* result_x,
            uint64_t* result_y);
}

namespace cryptofuzz {
namespace module {

pairing_ce::pairing_ce(void) :
    Module("pairing_ce") { }
namespace pairing_ce_detail {
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
            const std::array<uint64_t, 6>& result_x,
            const std::array<uint64_t, 6>& result_y) {
        const auto x = pairing_ce_detail::From6U64(result_x).ToTrimmedString();
        auto y = pairing_ce_detail::From6U64(result_y).ToTrimmedString();
        if (x == "0" && y == "1") {
            y = "0";
        }

        return component::G1{x, y};
    }
}

std::optional<bool> pairing_ce::OpBLS_IsG1OnCurve(operation::BLS_IsG1OnCurve& op) {
    std::optional<bool> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::array<uint64_t, 6>> ax, ay;

    CF_CHECK_NE(ax = pairing_ce_detail::To6U64(op.g1.first), std::nullopt);
    CF_CHECK_NE(ay = pairing_ce_detail::To6U64(op.g1.second), std::nullopt);

    {
        const auto res = pairing_ce_g1_isoncurve(
                ax->data(),
                ay->data());
        CF_CHECK_NE(res, -1);

        ret = res == 1;
    }

end:
    return ret;
}

std::optional<component::G1> pairing_ce::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::array<uint64_t, 6>> ax, ay, bx, by;
    std::array<uint64_t, 6> result_x, result_y;

    CF_CHECK_NE(ax = pairing_ce_detail::To6U64(op.a.first), std::nullopt);
    CF_CHECK_NE(ay = pairing_ce_detail::To6U64(op.a.second), std::nullopt);
    CF_CHECK_NE(bx = pairing_ce_detail::To6U64(op.b.first), std::nullopt);
    CF_CHECK_NE(by = pairing_ce_detail::To6U64(op.b.second), std::nullopt);

    CF_CHECK_NE(pairing_ce_g1_add(
                ax->data(),
                ay->data(),
                bx->data(),
                by->data(),
                result_x.data(),
                result_y.data()
                ), -1);

    ret = pairing_ce_detail::ToG1(result_x, result_y);

end:
    return ret;
}

std::optional<component::G1> pairing_ce::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::array<uint64_t, 6>> ax, ay;
    std::optional<std::array<uint64_t, 4>> b;
    std::array<uint64_t, 6> result_x, result_y;

    CF_CHECK_NE(ax = pairing_ce_detail::To6U64(op.a.first), std::nullopt);
    CF_CHECK_NE(ay = pairing_ce_detail::To6U64(op.a.second), std::nullopt);
    CF_CHECK_NE(b = pairing_ce_detail::To4U64(op.b), std::nullopt);

    CF_CHECK_NE(pairing_ce_g1_mul(
                ax->data(),
                ay->data(),
                b->data(),
                result_x.data(),
                result_y.data()
                ), -1);

    ret = pairing_ce_detail::ToG1(result_x, result_y);

end:
    return ret;
}

std::optional<component::G1> pairing_ce::OpBLS_G1_Neg(operation::BLS_G1_Neg& op) {
    std::optional<component::G1> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    std::optional<std::array<uint64_t, 6>> ax, ay;
    std::array<uint64_t, 6> result_x, result_y;

    CF_CHECK_NE(ax = pairing_ce_detail::To6U64(op.a.first), std::nullopt);
    CF_CHECK_NE(ay = pairing_ce_detail::To6U64(op.a.second), std::nullopt);

    CF_CHECK_NE(pairing_ce_g1_neg(
                ax->data(),
                ay->data(),
                result_x.data(),
                result_y.data()
                ), -1);

    ret = pairing_ce_detail::ToG1(result_x, result_y);

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
