#include "mutatorpool.h"

uint32_t PRNG(void);

template <class T, size_t Size>
void MutatorPool<T, Size>::Set(const T& v) {
    pool[PRNG() % Size] = v;
    set = true;
}

template <class T, size_t Size>
bool MutatorPool<T, Size>::Have(void) const {
	return set;
}

template <class T, size_t Size>
T MutatorPool<T, Size>::Get(void) const {
    return pool[PRNG() % Size];
}

MutatorPool<CurvePrivkey_Pair, 64> Pool_CurvePrivkey;
MutatorPool<CurveKeypair_Pair, 64> Pool_CurveKeypair;
MutatorPool<CurveECDSASignature_Pair, 64> Pool_CurveECDSASignature;
MutatorPool<std::string, 64> Pool_Bignum;
MutatorPool<std::string, 64> Pool_DH_PrivateKey;
MutatorPool<std::string, 64> Pool_DH_PublicKey;

template class MutatorPool<CurvePrivkey_Pair, 64>;
template class MutatorPool<CurveKeypair_Pair, 64>;
template class MutatorPool<CurveECDSASignature_Pair, 64>;
template class MutatorPool<std::string, 64>;
