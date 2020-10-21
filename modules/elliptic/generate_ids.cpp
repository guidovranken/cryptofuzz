#include <stdio.h>
#include <string>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include "../../repository_map.h"

int main(void) {
    printf("var IsNULL = function(id) { return id == BigInt(\"%zu\"); }\n", CF_DIGEST("NULL"));
    printf("var IsSHA256 = function(id) { return id == BigInt(\"%zu\"); }\n", CF_DIGEST("SHA256"));

    for (const auto item : ECC_CurveLUTMap ) {
        std::string name = item.second.name;
        printf("var Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }

    for (const auto item : OperationLUTMap ) {
        std::string name = item.second.name;
        printf("var Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }

    return 0;
}
