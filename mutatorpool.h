#pragma once

#include <array>
#include <string>
#include <cstdint>

template <class T, size_t Size>
class MutatorPool {
	private:
		std::array<T, Size> pool = {};
		bool set = false;
	public:
		void Set(const T& v);
		bool Have(void) const;
		T Get(void) const;
};

typedef struct {
    uint64_t curveID;
    std::string priv;
} CurvePrivkey_Pair;
extern MutatorPool<CurvePrivkey_Pair, 64> Pool_CurvePrivkey;

typedef struct {
    uint64_t curveID;
    std::string privkey;
    std::string pub_x;
    std::string pub_y;
} CurveKeypair_Pair;
extern MutatorPool<CurveKeypair_Pair, 64> Pool_CurveKeypair;

typedef struct {
    uint64_t curveID;
    std::string cleartext;
    std::string pub_x;
    std::string pub_y;
    std::string sig_r;
    std::string sig_y;
} CurveECDSASignature_Pair;
extern MutatorPool<CurveECDSASignature_Pair, 64> Pool_CurveECDSASignature;

extern MutatorPool<std::string, 64> Pool_Bignum;

extern MutatorPool<std::string, 64> Pool_DH_PrivateKey;
extern MutatorPool<std::string, 64> Pool_DH_PublicKey;
