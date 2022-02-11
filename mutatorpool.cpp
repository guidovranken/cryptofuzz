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

MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurvePrivkey;
MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveKeypair;
MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECDSASignature;
MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveECC_Point;
MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSSignature;
MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG1;
MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize> Pool_CurveBLSG2;
MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_Bignum;
MutatorPool<Fp12, cryptofuzz::config::kMutatorPoolSize> Pool_Fp12;
MutatorPool<BLS_BatchSignature_, cryptofuzz::config::kMutatorPoolSize> Pool_BLS_BatchSignature;
MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PrivateKey;
MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize> Pool_DH_PublicKey;

template class MutatorPool<CurvePrivkey_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveKeypair_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveECDSASignature_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveECC_Point_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSSignature_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG1_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<CurveBLSG2_Pair, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<Fp12, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<BLS_BatchSignature_, cryptofuzz::config::kMutatorPoolSize>;
template class MutatorPool<std::string, cryptofuzz::config::kMutatorPoolSize>;
