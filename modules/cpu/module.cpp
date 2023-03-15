#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

extern "C" {
    size_t cryptofuzz_asm_add(size_t, size_t);
    size_t cryptofuzz_asm_xadd(size_t, size_t);
    size_t cryptofuzz_asm_inc(size_t);
    size_t cryptofuzz_asm_sub(size_t, size_t);
    size_t cryptofuzz_asm_dec(size_t);
    size_t cryptofuzz_asm_div(size_t, size_t);
    size_t cryptofuzz_asm_mod(size_t, size_t);
    size_t cryptofuzz_asm_mul(size_t, size_t);
    size_t cryptofuzz_asm_or(size_t, size_t);
    size_t cryptofuzz_asm_xor(size_t, size_t);
    size_t cryptofuzz_asm_and(size_t, size_t);
    size_t cryptofuzz_asm_not(size_t);
    size_t cryptofuzz_asm_shl(size_t, uint8_t);
    size_t cryptofuzz_asm_shr(size_t, uint8_t);
    size_t cryptofuzz_asm_rol(size_t, uint8_t);
    size_t cryptofuzz_asm_ror(size_t, uint8_t);
    size_t cryptofuzz_asm_bsr(size_t);
    size_t cryptofuzz_asm_rdrand(void);
    size_t cryptofuzz_asm_crc32(const uint8_t*, size_t);
}

namespace cryptofuzz {
namespace module {

CPU::CPU(void) :
    Module("CPU") { }

namespace CPU_detail {
    template <class T>
    std::optional<T> Load(const component::Bignum& bn) {
        T ret = 0;
        const auto _d = util::DecToBin(bn.ToTrimmedString(), sizeof(T));
        if ( _d == std::nullopt ) {
            return std::nullopt;
        }
        auto d = *_d;
        std::reverse(d.begin(), d.end());
        memcpy(&ret, d.data(), d.size());
        return ret;
    }
}

std::optional<component::Digest> CPU::OpDigest(operation::Digest& op) {
    std::optional<component::Digest> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.digestType.Is(CF_DIGEST("CRC32-CPU")) ) {
        CF_CHECK_EQ(op.cleartext.GetSize() % 4, 0);

        static const std::array<uint8_t, 4> zeroes = {0};
        std::array<uint8_t, 8> resb;
        const auto res = cryptofuzz_asm_crc32(
                op.cleartext.GetPtr(&ds),
                op.cleartext.GetSize());
        memcpy(resb.data(), &res, resb.size());
        CF_ASSERT(
                !memcmp(zeroes.data(), resb.data() + 4, 4), "CRC32 output not zeroes");
        ret = component::Digest(resb.data(), 4);
    }

end:
    return ret;
}

std::optional<component::Bignum> CPU::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    if ( op.modulo == std::nullopt ||
         op.modulo->ToTrimmedString() != "18446744073709551616" ) {
        return std::nullopt;
    }

    size_t res = 0;
    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                res = cryptofuzz_asm_add(*A, *B);
            }
            break;
        case    CF_CALCOP("Sub(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                res = cryptofuzz_asm_sub(*A, *B);
            }
            break;
        case    CF_CALCOP("Mul(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                res = cryptofuzz_asm_mul(*A, *B);
            }
            break;
        case    CF_CALCOP("Div(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                CF_CHECK_NE(*B, 0);

                res = cryptofuzz_asm_div(*A, *B);
            }
            break;
        case    CF_CALCOP("Mod(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                CF_CHECK_NE(*B, 0);

                res = cryptofuzz_asm_mod(*A, *B);
            }
            break;
        case    CF_CALCOP("Or(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                res = cryptofuzz_asm_or(*A, *B);
            }
            break;
        case    CF_CALCOP("Xor(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                res = cryptofuzz_asm_xor(*A, *B);
            }
            break;
        case    CF_CALCOP("And(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<size_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                res = cryptofuzz_asm_and(*A, *B);
            }
            break;
        case    CF_CALCOP("RShift(A,B)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);

                auto B = CPU_detail::Load<uint8_t>(op.bn1);
                CF_CHECK_NE(B, std::nullopt);

                res = cryptofuzz_asm_shr(*A, *B);
            }
            break;
        case    CF_CALCOP("MSB(A)"):
            {
                auto A = CPU_detail::Load<size_t>(op.bn0);
                CF_CHECK_NE(A, std::nullopt);
                res = cryptofuzz_asm_bsr(*A);
            }
            break;
        case    CF_CALCOP("Rand()"):
            res = cryptofuzz_asm_rdrand();
        default:
            goto end;
    }

    ret = std::to_string(res);

end:

    return ret;
}

bool CPU::SupportsModularBignumCalc(void) const {
    return true;
}

} /* namespace module */
} /* namespace cryptofuzz */
