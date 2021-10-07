#include <stdio.h>
#include <string>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include <algorithm>
#include "../../repository_map.h"

int main(void) {
    for (const auto item : OperationLUTMap ) {
        std::string name = item.second.name;
        printf("var Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }
    for (const auto item : DigestLUTMap ) {
        std::string name = item.second.name;
        std::replace(name.begin(), name.end(), '-', '_');
        std::replace(name.begin(), name.end(), '.', '_');
        printf("var Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }

    return 0;
}
