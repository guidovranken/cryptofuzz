#include "module.h"
#include <cryptofuzz/util.h>
#include <cryptofuzz/crypto.h>
#include <ratpak.h>
#include <codecvt>
#include <locale>
#include <iostream>
#include "../../config.h"

namespace cryptofuzz {
namespace module {

MicrosoftCalculator::MicrosoftCalculator(void) :
    Module("Microsoft-Calculator") {
    ChangeConstants(10, 1);
}

namespace MicrosoftCalculator_detail {
    static component::Bignum FloatingPointToDecmal(std::string s) {
        if ( s == "0.0" ) {
            s = "0";
        } else {
            const size_t dotpos = s.find('.');
            if ( dotpos != std::string::npos ) {
                s.erase(dotpos, 1);
                const size_t epos = s.find('e');
                CF_ASSERT(epos != std::string::npos, "Expected e in floating point string");
                const auto exp = std::stoi(s.substr(epos + 1));
                s.erase(epos);
                s += std::string(exp - s.size() + 1, '0');
            }

            if (s.size() && s[0] == '0' && s == std::string(s.size(), '0')) {
                s = "0";
            }
        }

        return component::Bignum(s);
    }
}

std::optional<component::Bignum> MicrosoftCalculator::OpBignumCalc(operation::BignumCalc& op) {
    std::optional<component::Bignum> ret = std::nullopt;

    PNUMBER bn0 = nullptr;
    PNUMBER bn1 = nullptr;
    PNUMBER r = nullptr;

    CF_ASSERT(
        (bn0 = StringToNumber(
                std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(
                    op.bn0.ToTrimmedString()),
                10,
                config::kMaxBignumSize)) != nullptr,
        "Cannot load bignum into ratpack");
    CF_ASSERT(
        (bn1 = StringToNumber(
                std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(
                    op.bn1.ToTrimmedString()),
                10,
                config::kMaxBignumSize)) != nullptr,
        "Cannot load bignum into ratpack");

    switch ( op.calcOp.Get() ) {
        case    CF_CALCOP("Add(A,B)"):
            CF_NORET(addnum(&bn0, bn1, 10));
            r = bn0;
            break;
        case    CF_CALCOP("Mul(A,B)"):
            CF_NORET(mulnum(&bn0, bn1, 10));
            r = bn0;
            break;
        default:
            goto end;
    }

    {
        const auto ws = NumberToString(r,
                NumberFormat::Float,
                10, r->cdigit + 1);
        auto s = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(ws);
        ret = MicrosoftCalculator_detail::FloatingPointToDecmal(s);
    }

end:
    destroynum(bn0);
    destroynum(bn1);

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
