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

    write(fp, ID("Cryptofuzz/Operation/Digest") );
    write(fp, ID("Cryptofuzz/Operation/HMAC") );
    write(fp, ID("Cryptofuzz/Operation/SymmetricDecrypt") );
    write(fp, ID("Cryptofuzz/Operation/SymmetricEncrypt") );
    write(fp, ID("Cryptofuzz/Operation/KDF_SCRYPT") );
    write(fp, ID("Cryptofuzz/Operation/KDF_HKDF") );
    write(fp, ID("Cryptofuzz/Operation/KDF_TLS1_PRF") );
    write(fp, ID("Cryptofuzz/Operation/KDF_PBKDF2") );
    write(fp, ID("Cryptofuzz/Operation/CMAC") );
    write(fp, ID("Cryptofuzz/Operation/Sign") );
    write(fp, ID("Cryptofuzz/Operation/Verify") );

    for (const auto digest : DigestLUTMap ) {
        write(fp, digest.first);
    }

    for (const auto cipher : CipherLUTMap ) {
        write(fp, cipher.first);
    }

    fclose(fp);

    return 0;
}
