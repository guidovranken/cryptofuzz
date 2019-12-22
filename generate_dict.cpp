#include <cstdint>
#include <cstddef>
#include <sstream>
#include <iomanip>
#include <vector>
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
static void writeMap(FILE* fp, const T& map) {
    for (const auto item : map ) {
        write(fp, item.first);
    }
}

static void writeBuffer(FILE* fp, const size_t size) {
    if ( size > 255 ) {
        printf("Sizes > 255 unsupported\n");
        abort();
    }

    std::stringstream ss;

    ss << "\"";

    for (size_t i = 0; i < 4 + size; i++) {
        if ( i == 0 ) {
            ss << "\\x" << std::setfill('0') << std::setw(2) << std::hex << size;
        } else {
            ss << "\\x00";
        }
    }

    ss << "\"";

    fprintf(fp, "%s\n", ss.str().c_str());
}

int main(void)
{
    using fuzzing::datasource::ID;

    FILE* fp = fopen("cryptofuzz-dict.txt", "wb");

    writeMap(fp, ModuleLUTMap);
    writeMap(fp, OperationLUTMap);
    writeMap(fp, DigestLUTMap);
    writeMap(fp, CipherLUTMap);
    writeMap(fp, ECC_CurveLUTMap);
    writeMap(fp, CalcOpLUTMap);

    {
        const std::vector<uint8_t> bufferSizes = {1, 2, 4, 8, 12, 16, 32};
        for (const auto& size : bufferSizes) {
            writeBuffer(fp, size);
        }

    }

    fclose(fp);

    return 0;
}
