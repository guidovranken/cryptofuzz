#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

/* https://github.com/NethermindEth/nethermind/blob/master/src/Nethermind/Nethermind.Crypto/runtimes/linux-x64/native/libshamatar.so */

extern "C" {
uint32_t eip196_perform_operation(
        uint8_t operation,
        uint8_t* input,
        uint32_t inputLength,
        uint8_t* output,
        uint32_t* outputLength,
        uint8_t* error,
        uint32_t* errorLength);
}

namespace cryptofuzz {
namespace module {

Shamatar::Shamatar(void) :
    Module("Shamatar") { }

std::optional<component::G1> Shamatar::OpBLS_G1_Add(operation::BLS_G1_Add& op) {
    std::optional<component::G1> ret = std::nullopt;

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes, b_x_bytes, b_y_bytes;
    std::array<uint8_t, 128> input;
    std::array<uint8_t, 64> output;
    uint32_t outputLength = 64;
    uint8_t error[256] = {0};
    uint32_t errorLength = sizeof(error);

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
    memcpy(input.data(), a_x_bytes->data(), 32);

    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);
    memcpy(input.data() + 32, a_y_bytes->data(), 32);

    CF_CHECK_NE(b_x_bytes = util::DecToBin(op.b.first.ToTrimmedString(), 32), std::nullopt);
    memcpy(input.data() + 64, b_x_bytes->data(), 32);

    CF_CHECK_NE(b_y_bytes = util::DecToBin(op.b.second.ToTrimmedString(), 32), std::nullopt);
    memcpy(input.data() + 96, b_y_bytes->data(), 32);

    if ( eip196_perform_operation(
                1,
                input.data(), 128,
                output.data(), &outputLength,
                error, &errorLength) == 0 ) {
        ret = component::G1{
            util::BinToDec(output.data(), 32),
            util::BinToDec(output.data() + 32, 32),
        };
    } else {
        ret = component::G1{"0", "0"};
    }

end:
    return ret;
}

std::optional<component::G1> Shamatar::OpBLS_G1_Mul(operation::BLS_G1_Mul& op) {
    std::optional<component::G1> ret = std::nullopt;

    std::optional<std::vector<uint8_t>> a_x_bytes, a_y_bytes, b_x_bytes, b_y_bytes;
    std::array<uint8_t, 96> input;
    std::array<uint8_t, 64> output;
    uint32_t outputLength = 64;
    uint8_t error[256] = {0};
    uint32_t errorLength = sizeof(error);

    CF_CHECK_NE(a_x_bytes = util::DecToBin(op.a.first.ToTrimmedString(), 32), std::nullopt);
    memcpy(input.data(), a_x_bytes->data(), 32);

    CF_CHECK_NE(a_y_bytes = util::DecToBin(op.a.second.ToTrimmedString(), 32), std::nullopt);
    memcpy(input.data() + 32, a_y_bytes->data(), 32);

    CF_CHECK_NE(b_x_bytes = util::DecToBin(op.b.ToTrimmedString(), 32), std::nullopt);
    memcpy(input.data() + 64, b_x_bytes->data(), 32);

    if ( eip196_perform_operation(
                2,
                input.data(), 96,
                output.data(), &outputLength,
                error, &errorLength) == 0 ) {
        ret = component::G1{
            util::BinToDec(output.data(), 32),
            util::BinToDec(output.data() + 32, 32),
        };
    } else {
        ret = component::G1{"0", "0"};
    }

end:
    return ret;
}
        
std::optional<bool> Shamatar::OpBLS_BatchVerify(operation::BLS_BatchVerify& op) {
    std::optional<bool> ret = std::nullopt;

    std::vector<uint8_t> input;
    std::array<uint8_t, 64> output;
    uint32_t outputLength = 32;
    uint8_t error[256] = {0};
    uint32_t errorLength = sizeof(error);

    for (const auto& cur : op.bf.c) {
        std::optional<std::vector<uint8_t>> a_x, a_y, b_v, b_w, b_x, b_y;
        CF_CHECK_NE(a_x = cur.g1.first.ToBin(32), std::nullopt);
        CF_CHECK_NE(a_y = cur.g1.second.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_v = cur.g2.first.first.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_w = cur.g2.first.second.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_x = cur.g2.second.first.ToBin(32), std::nullopt);
        CF_CHECK_NE(b_y = cur.g2.second.second.ToBin(32), std::nullopt);

        input.insert(input.end(), a_x->begin(), a_x->end());
        input.insert(input.end(), a_y->begin(), a_y->end());
        input.insert(input.end(), b_v->begin(), b_v->end());
        input.insert(input.end(), b_x->begin(), b_x->end());
        input.insert(input.end(), b_w->begin(), b_w->end());
        input.insert(input.end(), b_y->begin(), b_y->end());
    }

    if ( eip196_perform_operation(
                3,
                input.data(), input.size(),
                output.data(), &outputLength,
                error, &errorLength) == 0 ) {
        static const std::vector<uint8_t> zero(32, 0);
        if ( std::vector<uint8_t>(output.data(), output.data() + outputLength) == zero ) {
            ret = false;
        } else {
            ret = true;
        }
    } else {
        ret = false;
    }

end:
    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
