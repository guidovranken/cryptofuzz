#include <cstdint>
#include <cstddef>
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
        std::string s;
        fprintf(fp,
                "pub fn is_%s(algorithm: u64) -> bool { if algorithm == %s { true } else { false } }\n",
                digestStr.c_str(), std::to_string(digest.first).c_str());
    }
    fclose(fp);
}
