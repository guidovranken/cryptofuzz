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
        fprintf(fp, "func is%s(id uint64) bool { return id == %zu }\n", digestStr.c_str(), digest.first);
    }
    for (const auto cipher : CipherLUTMap ) {
        auto cipherStr = std::string(cipher.second.name);
        cipherStr = std::regex_replace(cipherStr, std::regex("[.-]"), "_");
        if ( cipherStr == "GOST_28147_89" ) {
            /* XXX */
            continue;
        }
        fprintf(fp, "func is%s(id uint64) bool { return id == %zu }\n", cipherStr.c_str(), cipher.first);
    }
    fclose(fp);
}
