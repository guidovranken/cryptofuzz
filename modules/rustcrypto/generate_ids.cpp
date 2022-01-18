#include <cstdint>
#include <cstddef>
#include <algorithm>
#include <cctype>
#include <stdio.h>
#include <regex>
#include <fuzzing/datasource/id.hpp>
#include "../../repository_map.h"

int main(void)
{
    FILE* fp = fopen("ids.rs", "wb");
    for (const auto& digest : DigestLUTMap ) {
        auto digestStr = std::string(digest.second.name);
        digestStr = std::regex_replace(digestStr, std::regex("[.-]"), "_");
        std::transform(digestStr.begin(), digestStr.end(), digestStr.begin(),
                [](unsigned char c){ return std::tolower(c); });
        std::string s;
        fprintf(fp,
                "#[allow(dead_code)]\n"
                "pub fn is_%s(algorithm: u64) -> bool { if algorithm == %s { true } else { false } }\n",
                digestStr.c_str(), std::to_string(digest.first).c_str());
    }
    for (const auto& bnOp : CalcOpLUTMap ) {
        auto bnOpStr = std::string(bnOp.second.name);
        bnOpStr = std::regex_replace(bnOpStr, std::regex("\\(.*"), "");
        std::transform(bnOpStr.begin(), bnOpStr.end(), bnOpStr.begin(),
                [](unsigned char c){ return std::tolower(c); });
        fprintf(fp,
                "#[allow(dead_code)]\n"
                "pub fn is_%s(calcop: u64) -> bool { if calcop == %s { true } else { false } }\n",
                bnOpStr.c_str(), std::to_string(bnOp.first).c_str());
    }
    for (const auto& cipher : CipherLUTMap ) {
        auto cipherStr = std::string(cipher.second.name);
        cipherStr = std::regex_replace(cipherStr, std::regex("\\(.*"), "");
        cipherStr = std::regex_replace(cipherStr, std::regex("-"), "_");
        std::transform(cipherStr.begin(), cipherStr.end(), cipherStr.begin(),
                [](unsigned char c){ return std::tolower(c); });
        fprintf(fp,
                "#[allow(dead_code)]\n"
                "pub fn is_cipher_%s(cipher: u64) -> bool { if cipher == %s { true } else { false } }\n",
                cipherStr.c_str(), std::to_string(cipher.first).c_str());
    }
    for (const auto& curve : ECC_CurveLUTMap ) {
        auto curveStr = std::string(curve.second.name);
        curveStr = std::regex_replace(curveStr, std::regex("\\(.*"), "");
        std::transform(curveStr.begin(), curveStr.end(), curveStr.begin(),
                [](unsigned char c){ return std::tolower(c); });
        fprintf(fp,
                "#[allow(dead_code)]\n"
                "pub fn is_%s(curve: u64) -> bool { if curve == %s { true } else { false } }\n",
                curveStr.c_str(), std::to_string(curve.first).c_str());
    }
    fclose(fp);
}
