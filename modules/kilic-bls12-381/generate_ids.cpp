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
    for (const auto bnOp : CalcOpLUTMap ) {
        auto bnOpStr = std::string(bnOp.second.name);
        bnOpStr = std::regex_replace(bnOpStr, std::regex("\\(.*"), "");
        fprintf(fp, "func is%s(id Type) bool { return id == %s }\n", bnOpStr.c_str(), std::to_string(bnOp.first).c_str());
    }
    fclose(fp);
}
