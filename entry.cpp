#include <cstddef>
#include <cstdint>
#include <memory>
#include <set>
#include <vector>
#include <string>
#include <cryptofuzz/options.h>
#include <fuzzing/datasource/id.hpp>
#include "repository_tbl.h"
#include "driver.h"
#include "numbers.h"

#if defined(CRYPTOFUZZ_LIBTOMMATH) && defined(CRYPTOFUZZ_NSS)
#error "libtommath and NSS cannot be used together due to symbol collisions"
#endif

#if defined(CRYPTOFUZZ_TREZOR_FIRMWARE) && defined(CRYPTOFUZZ_RELIC)
#error "trezor-firmware and relic cannot be used together due to symbol collisions"
#endif

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

#if defined(CRYPTOFUZZ_LINUX)
  #include <modules/linux/module.h>
#endif

#if defined(CRYPTOFUZZ_SYMCRYPT)
  #include <modules/symcrypt/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBTOMMATH)
  #include <modules/libtommath/module.h>
#endif

#if defined(CRYPTOFUZZ_SJCL)
  #include <modules/sjcl/module.h>
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
  #include <modules/wolfcrypt-openssl/module.h>
#endif

#if defined(CRYPTOFUZZ_MONOCYPHER)
  #include <modules/monocypher/module.h>
#endif

#if defined(CRYPTOFUZZ_SECP256K1)
  #include <modules/secp256k1/module.h>
#endif

#if defined(CRYPTOFUZZ_RUST_LIBSECP256K1)
  #include <modules/rust-libsecp256k1/module.h>
#endif

#if defined(CRYPTOFUZZ_TREZOR_FIRMWARE)
  #include <modules/trezor/module.h>
#endif

#if defined(CRYPTOFUZZ_ELLIPTIC)
  #include <modules/elliptic/module.h>
#endif

#if defined(CRYPTOFUZZ_DECRED)
  #include <modules/decred/module.h>
#endif

#if defined(CRYPTOFUZZ_BEARSSL)
  #include <modules/bearssl/module.h>
#endif

#if defined(CRYPTOFUZZ_MICRO_ECC)
  #include <modules/micro-ecc/module.h>
#endif

#if defined(CRYPTOFUZZ_CIFRA)
  #include <modules/cifra/module.h>
#endif

#if defined(CRYPTOFUZZ_RELIC)
  #include <modules/relic/module.h>
#endif

#if defined(CRYPTOFUZZ_LIBECC)
  #include <modules/libecc/module.h>
#endif

#if defined(CRYPTOFUZZ_CHIA_BLS)
  #include <modules/chia_bls/module.h>
#endif

std::shared_ptr<cryptofuzz::Driver> driver = nullptr;

const cryptofuzz::Options* cryptofuzz_options = nullptr;

static void setOptions(int argc, char** argv) {
    std::vector<std::string> extraArguments;

    const std::string cmdline(
#include "extra_options.h"
    );
    boost::split(extraArguments, cmdline, boost::is_any_of(" "));

    const cryptofuzz::Options options(argc, argv, extraArguments);

    driver = std::make_shared<cryptofuzz::Driver>(options);
    cryptofuzz_options = driver->GetOptionsPtr();
}

static void addNumbers(void) {
    std::set<std::string> curveNumbers;

    for (size_t i = 0; i < (sizeof(ECC_CurveLUT) / sizeof(ECC_CurveLUT[0])); i++) {
        if ( ECC_CurveLUT[i].prime ) curveNumbers.insert(*ECC_CurveLUT[i].prime);
        if ( ECC_CurveLUT[i].a ) curveNumbers.insert(*ECC_CurveLUT[i].a);
        if ( ECC_CurveLUT[i].b ) curveNumbers.insert(*ECC_CurveLUT[i].b);
        if ( ECC_CurveLUT[i].x ) curveNumbers.insert(*ECC_CurveLUT[i].x);
        if ( ECC_CurveLUT[i].y ) curveNumbers.insert(*ECC_CurveLUT[i].y);
        if ( ECC_CurveLUT[i].order_min_1 ) curveNumbers.insert(*ECC_CurveLUT[i].order_min_1);
        if ( ECC_CurveLUT[i].order ) curveNumbers.insert(*ECC_CurveLUT[i].order);
    }

    for (const auto& s : curveNumbers) {
        cryptofuzz::numbers.push_back(s);
    }
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    setOptions(*argc, *argv);
    addNumbers();

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

#if defined(CRYPTOFUZZ_LINUX)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Linux>() );
#endif

#if defined(CRYPTOFUZZ_SYMCRYPT)
    driver->LoadModule( std::make_shared<cryptofuzz::module::SymCrypt>() );
#endif

#if defined(CRYPTOFUZZ_LIBTOMMATH)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libtommath>() );
#endif

#if defined(CRYPTOFUZZ_SJCL)
    driver->LoadModule( std::make_shared<cryptofuzz::module::sjcl>() );
#endif

#if defined(CRYPTOFUZZ_WOLFCRYPT_OPENSSL)
    driver->LoadModule( std::make_shared<cryptofuzz::module::wolfCrypt_OpenSSL>() );
#endif

#if defined(CRYPTOFUZZ_MONOCYPHER)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Monocypher>() );
#endif

#if defined(CRYPTOFUZZ_SECP256K1)
    driver->LoadModule( std::make_shared<cryptofuzz::module::secp256k1>() );
#endif

#if defined(CRYPTOFUZZ_RUST_LIBSECP256K1)
    driver->LoadModule( std::make_shared<cryptofuzz::module::rust_libsecp256k1>() );
#endif

#if defined(CRYPTOFUZZ_TREZOR_FIRMWARE)
    driver->LoadModule( std::make_shared<cryptofuzz::module::trezor_firmware>() );
#endif

#if defined(CRYPTOFUZZ_ELLIPTIC)
    driver->LoadModule( std::make_shared<cryptofuzz::module::elliptic>() );
#endif

#if defined(CRYPTOFUZZ_DECRED)
    driver->LoadModule( std::make_shared<cryptofuzz::module::Decred>() );
#endif

#if defined(CRYPTOFUZZ_BEARSSL)
    driver->LoadModule( std::make_shared<cryptofuzz::module::BearSSL>() );
#endif

#if defined(CRYPTOFUZZ_MICRO_ECC)
    driver->LoadModule( std::make_shared<cryptofuzz::module::micro_ecc>() );
#endif

#if defined(CRYPTOFUZZ_CIFRA)
    driver->LoadModule( std::make_shared<cryptofuzz::module::cifra>() );
#endif

#if defined(CRYPTOFUZZ_RELIC)
    driver->LoadModule( std::make_shared<cryptofuzz::module::relic>() );
#endif

#if defined(CRYPTOFUZZ_LIBECC)
    driver->LoadModule( std::make_shared<cryptofuzz::module::libecc>() );
#endif

#if defined(CRYPTOFUZZ_CHIA_BLS)
    driver->LoadModule( std::make_shared<cryptofuzz::module::chia_bls>() );
#endif

    /* TODO check if options.forceModule (if set) refers to a module that is
     * actually loaded, warn otherwise.
     */
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    driver->Run(data, size);

    return 0;
}
