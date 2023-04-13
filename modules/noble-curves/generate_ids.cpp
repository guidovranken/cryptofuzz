#include <stdio.h>
#include <string>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/repository.h>
#include "../../repository_map.h"

int main(void) {
    for (const auto item : DigestLUTMap ) {
        std::string name = item.second.name;
        const auto pos = name.find_first_of("-");
        /* XXX */
        if ( pos != std::string::npos ) {
            continue;
        }
        name = name.substr(0, pos);
        printf("export const Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }

    for (const auto item : OperationLUTMap ) {
        std::string name = item.second.name;
        printf("export const Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }

    for (const auto item : CipherLUTMap ) {
        std::string name = item.second.name;
        if ( name.find("-") != std::string::npos ) {
            continue;
        }
        printf("export const Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }

    for (const auto item : CalcOpLUTMap ) {
        std::string name = item.second.name;
        const auto pos = name.find_first_of("(");
        if ( pos == std::string::npos ) {
            /* should never happen */
            abort();
        }
        name = name.substr(0, pos);
        printf("export const Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }
    // requires & by some reasons
    for (const auto& item : ECC_CurveLUTMap ) {
        std::string name = item.second.name;
        printf("export const Is%s = function(id) { return id == BigInt(\"%zu\"); }\n", name.c_str(), item.first);
    }

    return 0;
}
