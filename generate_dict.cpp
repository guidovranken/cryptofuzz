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

    write(fp, ID("Cryptofuzz/Module/Beast") );
    write(fp, ID("Cryptofuzz/Module/CPPCrypto") );
    write(fp, ID("Cryptofuzz/Module/Crypto++") );
    write(fp, ID("Cryptofuzz/Module/EverCrypt") );
    write(fp, ID("Cryptofuzz/Module/Monero") );
    write(fp, ID("Cryptofuzz/Module/OpenSSL") );
    write(fp, ID("Cryptofuzz/Module/Public Domain") );
    write(fp, ID("Cryptofuzz/Module/Veracrypt") );
    write(fp, ID("Cryptofuzz/Module/libgcrypt") );
    write(fp, ID("Cryptofuzz/Module/libsodium") );
    write(fp, ID("Cryptofuzz/Module/mbed TLS") );
    write(fp, ID("Cryptofuzz/Module/Golang") );

    writeMap(fp, OperationLUTMap);
    writeMap(fp, DigestLUTMap);
    writeMap(fp, CipherLUTMap);

    fclose(fp);

    return 0;
}
