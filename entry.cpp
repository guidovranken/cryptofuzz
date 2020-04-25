#include <cstddef>
#include <cstdint>
#include <memory>
#include "driver.h"

#if !defined(CRYPTOFUZZ_NO_OPENSSL)
  #include <modules/openssl/module.h>
#endif

#if defined(CRYPTOFUZZ_BITCOIN)
  #include <modules/bitcoin/module.h>
#endif

#if defined(CRYPTOFUZZ_REFERENCE)
  #include <modules/reference/module.h>
#endif

#if defined(CRYPTOFUZZ_CPPCRYPTO)
  #include <modules/cppcrypto/module.h>
#endif

#if defined(CRYPTOFUZZ_MBEDTLS)
  #include <modules/mbedtls/module.h>
#endif

#if defined(CRYPTOFUZZ_BOOST)
  #include <modules/boost/module.h>
#endif

#if defined(CRYPTOFUZZ_MONERO)
  #include <modules/monero/module.h>
#endif

#if defined(CRYPTOFUZZ_VERACRYPT)
  #include <modules/veracrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBSODIUM)
  #include <modules/libsodium/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBTOMCRYPT)
  #include <modules/libtomcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_CRYPTOPP)
  #include <modules/cryptopp/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBGCRYPT)
  #include <modules/libgcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_EVERCRYPT)
  #include <modules/evercrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_GOLANG)
  #include <modules/golang/module.h>
#endif

#if defined(CRYPTOFUZZ_NSS)
  #include <modules/nss/module.h>
#endif

#if defined(CRYPTOFUZZ_BOTAN)
  #include <modules/botan/module.h>
#endif

#if defined(CRYPTOFUZZ_NETTLE)
  #include <modules/nettle/module.h>
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT)
  #include <modules/wolfcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBGMP)
  #include <modules/libgmp/module.h>
#endif

#if defined(CRYPTOFUZZ_BN_JS)
  #include <modules/bn.js/module.h>
#endif

#if defined(CRYPTOFUZZ_CRYPTO_JS)
  #include <modules/crypto-js/module.h>
#endif

#if defined(CRYPTOFUZZ_BIGNUMBER_JS)
  #include <modules/bignumber.js/module.h>
#endif

#if defined(CRYPTOFUZZ_MPDECIMAL)
  #include <modules/mpdecimal/module.h>
#endif

std::shared_ptr<cryptofuzz::Driver> driver = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    bool debug = false;

    for (int i = 1; i < *argc; i++) {
        const std::string arg((*argv)[i]);

        if ( arg == "--debug") {
            debug = true;
        }
    }

    driver = std::make_shared<cryptofuzz::Driver>(debug);

#if !defined(CRYPTOFUZZ_NO_OPENSSL)
    driver->LoadModule( std::make_shared<cryptofuzz::module::OpenSSL>() );
#endif

#if defined(CRYPTOFUZZ_BITCOIN)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Bitcoin>() );
#endif

#if defined(CRYPTOFUZZ_REFERENCE)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Reference>() );
#endif

#if defined(CRYPTOFUZZ_CPPCRYPTO)
    driver->LoadModule( std::make_shared<cryptofuzz::module::CPPCrypto>() );
#endif

#if defined(CRYPTOFUZZ_MBEDTLS)
    driver->LoadModule( std::make_shared<cryptofuzz::module::mbedTLS>() );
#endif

#if defined(CRYPTOFUZZ_BOOST)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Boost>() );
#endif

#if defined(CRYPTOFUZZ_MONERO)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Monero>() );
#endif

#if defined(CRYPTOFUZZ_VERACRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Veracrypt>() );
#endif

#if defined(CRYPTOFUZZ_LIBSODIUM)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libsodium>() );
#endif

#if defined(CRYPTOFUZZ_LIBTOMCRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libtomcrypt>() );
#endif

#if defined(CRYPTOFUZZ_CRYPTOPP)
    driver->LoadModule( std::make_shared<cryptofuzz::module::CryptoPP>() );
#endif

#if defined(CRYPTOFUZZ_LIBGCRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libgcrypt>() );
#endif

#if defined(CRYPTOFUZZ_EVERCRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::EverCrypt>() );
#endif

#if defined(CRYPTOFUZZ_GOLANG)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Golang>() );
#endif

#if defined(CRYPTOFUZZ_NSS)
    driver->LoadModule( std::make_shared<cryptofuzz::module::NSS>() );
#endif

#if defined(CRYPTOFUZZ_BOTAN)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Botan>() );
#endif

#if defined(CRYPTOFUZZ_NETTLE)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Nettle>() );
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::wolfCrypt>() );
#endif

#if defined(CRYPTOFUZZ_LIBGMP)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libgmp>() );
#endif

#if defined(CRYPTOFUZZ_BN_JS)
    driver->LoadModule( std::make_shared<cryptofuzz::module::bn_js>() );
#endif

#if defined(CRYPTOFUZZ_CRYPTO_JS)
    driver->LoadModule( std::make_shared<cryptofuzz::module::crypto_js>() );
#endif

#if defined(CRYPTOFUZZ_BIGNUMBER_JS)
    driver->LoadModule( std::make_shared<cryptofuzz::module::bignumber_js>() );
#endif

#if defined(CRYPTOFUZZ_MPDECIMAL)
    driver->LoadModule( std::make_shared<cryptofuzz::module::mpdecimal>() );
#endif
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    driver->Run(data, size);

    return 0;
}
