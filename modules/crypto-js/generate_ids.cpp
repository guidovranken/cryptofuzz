#include <stdio.h>
#include <fuzzing/datasource/id.hpp>
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
        printf("var Is%s = function(id) { return id == %zu; }\n", name.c_str(), item.first);
    }

    for (const auto item : OperationLUTMap ) {
        std::string name = item.second.name;
        printf("var Is%s = function(id) { return id == %zu; }\n", name.c_str(), item.first);
    }

    return 0;
}
