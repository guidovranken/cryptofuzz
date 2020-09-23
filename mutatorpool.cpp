#include "mutatorpool.h"

std::array<CurvePrivkey_Pair, 64> Pool_CurvePrivkey;
std::array<CurveKeypair_Pair, 64> Pool_CurveKeypair;
std::array<CurveECDSASignature_Pair, 64> Pool_CurveECDSASignature;
std::array<std::string, 64> Pool_Bignum;

#if 0

template <class T, size_t Size>
class MutatorPool {
	private:
		std::array<T, Size> pool;
		bool set;
	public:
		void Set(const T& v);
		bool Have(void) const;
		T Get(void) const;
}

void MutatorPool::Set(const T& v) const {
}

bool MutatorPool::Have(void) const {
	return set;
}

T MutatorPool::Get(void) const {
}
#endif
