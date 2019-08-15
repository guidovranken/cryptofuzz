#include <cstdint>
#include <cstddef>
#include <stdio.h>
#include <fuzzing/datasource/id.hpp>
#include "repository_map.h"

static void write(FILE* fp, uint64_t val) {

    fprintf(fp, "\"");
    for (size_t i = 0; i < 8; i++) {
        fprintf(fp, "\\x%02X", (uint8_t)(val & 0xFF));
        val >>= 8;
    }
    fprintf(fp, "\"\n");
}

template <class T>
static void writeMap(FILE* fp, T& map) {
    for (const auto item : map ) {
        write(fp, item.first);
    }
}

int main(void)
{
    using fuzzing::datasource::ID;

    FILE* fp = fopen("cryptofuzz-dict.txt", "wb");

    writeMap(fp, ModuleLUTMap);
    writeMap(fp, OperationLUTMap);
    writeMap(fp, DigestLUTMap);
    writeMap(fp, CipherLUTMap);

    fclose(fp);

    return 0;
}
