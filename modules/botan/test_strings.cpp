#include <cstdint>
#include <map>
#include <cryptofuzz/repository.h>
#include <botan/hash.h>
#include <botan/cipher_mode.h>

static void test_digests(void) {
#include "digest_string_lut.h"
    for (auto it = LUT.begin(); it != LUT.end(); it++) {
        /* SipHash is not an actual digest function, so skip */
        if ( it->second == "SipHash" ) {
            continue;
        }

        const auto hash = ::Botan::HashFunction::create(it->second);

        if ( hash == nullptr ) {
            printf("Cannot instantiate digest: %s\n", it->second.c_str());
        }
    }
}

static void test_ciphers(void) {
#include "cipher_string_lut.h"
    for (auto it = LUT.begin(); it != LUT.end(); it++) {
        const auto crypt = ::Botan::Cipher_Mode::create(it->second.first, ::Botan::ENCRYPTION);
        if ( crypt == nullptr ) {
            printf("Cannot instantiate cipher: %s\n", it->second.first.c_str());
        }
    }
}

int main(void) {
    test_digests();
    test_ciphers();

    return 0;
}
