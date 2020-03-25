#include <cstdint>
#include <cstddef>
#include <stdio.h>
#include <regex>
#include <fuzzing/datasource/id.hpp>
#include "../../repository_map.h"

int main(void)
{
    FILE* fp = fopen("ids.go", "wb");
    fprintf(fp, "package main\n");
    for (const auto digest : DigestLUTMap ) {
        auto digestStr = std::string(digest.second.name);
        digestStr = std::regex_replace(digestStr, std::regex("[.-]"), "_");
        fprintf(fp, "func is%s(id uint64) bool { return id == %s }\n", digestStr.c_str(), std::to_string(digest.first).c_str());
    }
    for (const auto cipher : CipherLUTMap ) {
        auto cipherStr = std::string(cipher.second.name);
        cipherStr = std::regex_replace(cipherStr, std::regex("[.-]"), "_");
        if ( cipherStr == "GOST_28147_89" ) {
            /* XXX */
            continue;
        }
        fprintf(fp, "func is%s(id uint64) bool { return id == %s }\n", cipherStr.c_str(), std::to_string(cipher.first).c_str());
    }
    for (const auto curve : ECC_CurveLUTMap ) {
        auto curveStr = std::string(curve.second.name);
        curveStr = std::regex_replace(curveStr, std::regex("[.-]"), "_");
        fprintf(fp, "func is%s(id uint64) bool { return id == %s }\n", curveStr.c_str(), std::to_string(curve.first).c_str());
    }
    for (const auto bnOp : CalcOpLUTMap ) {
        auto bnOpStr = std::string(bnOp.second.name);
        bnOpStr = std::regex_replace(bnOpStr, std::regex("\\(.*"), "");
        fprintf(fp, "func is%s(id uint64) bool { return id == %s }\n", bnOpStr.c_str(), std::to_string(bnOp.first).c_str());
    }
    fclose(fp);
}
