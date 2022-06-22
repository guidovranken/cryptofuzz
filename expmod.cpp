#include "expmod.h"
#include <boost/random.hpp>
#include <fuzzing/datasource/id.hpp>
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include "repository_tbl.h"
#include "config.h"

uint32_t PRNG(void);
std::string getBignum(bool mustBePositive = false);
std::string getPrime(void);

namespace cryptofuzz {
namespace mutator {
namespace ExpModGenerator {
    using namespace boost::multiprecision;
    using namespace boost::random;

    static mt19937 mt;

    inline bool is_even(const cpp_int& v) {
        return (v & 1) == 0;
    }

    inline bool is_odd(const cpp_int& v) {
        return (v & 1) == 1;
    }

    inline nlohmann::json to_json(const cpp_int& B, const cpp_int& E, const cpp_int& M) {
        nlohmann::json ret;

        ret["modifier"] = "";
        ret["calcOp"] = CF_CALCOP("ExpMod(A,B,C)");
        ret["bn1"] = B.str();
        ret["bn2"] = E.str();
        ret["bn3"] = M.str();
        ret["bn4"] = "";

        return ret;
    }

    inline const cpp_int& max(void) {
        static const cpp_int max(std::string(cryptofuzz::config::kMaxBignumSize, '9'));
        return max;
    }

    inline cpp_int max_multiplier(const cpp_int& v, const cpp_int& m) {
        return v == 0 ? cpp_int(0) : m / v;
    }

    inline cpp_int max_multiplier(const cpp_int& v) {
        return max_multiplier(v, max());
    }

    /* Multiply 'v' by a random positive integer m such that v * m < max() */
    /* If that is not possible, return false, else return true.
     */
    inline bool multiply_random(cpp_int& v, const bool odd = false) {
        const cpp_int max_mul = max_multiplier(v);

        if ( max_mul == 0 ) {
            return false;
        }

        cpp_int mul = uniform_int_distribution<cpp_int>(1, max_mul)(mt);

        if ( odd && is_even(mul) ) {
            mul--;
            //assert(mul > 0);
        }

        v *= mul;

        return true;
    }

    /* If 'a' and 'b' are such that a * b < max(), then
     * perform the multiplication on 'a' and return true.
     * Return false otherwise.
     */
    inline bool multiply(cpp_int& a, const cpp_int& b) {
        /* XXX return a <= max() / b; */
        const cpp_int max_mul = max_multiplier(a);

        if ( max_mul < b ) {
            return false;
        }

        a *= b;

        return true;
    }

    inline cpp_int get_prime(void) {
        const cpp_int p(getPrime());

        if ( p > 0 ) {
            return p;
        }

        /* Prime pool is empty, fall back to regular number */
        return cpp_int(getBignum(true));
    }

    inline std::vector<size_t> prime_factors(const cpp_int& v) noexcept {
        static const std::vector<size_t> primes{2, 3, 5, 7, 11, 13, 17, 19};

        std::vector<size_t> ret;

        for (const auto& p : primes) {
            if ( v % p == 0 ) {
                ret.push_back(p);
            }
        }

        return ret;
    }

    /* Compute max E such that base^E <= v */
    inline size_t log(const cpp_int& v, const cpp_int& base) {
        size_t i = 0;
        auto x = base;
        while ( x <= v ) {
            x *= base;
            i++;
        }
        return i;
    }

    /* This is slightly faster than native boost::multiprecision::pow */
    inline cpp_int pow(const cpp_int& v, const size_t exponent) {
        if ( exponent == 0 ) {
            static const cpp_int one(1);
            return one;
        } else if ( exponent == 1 ) {
            return v;
        } else {
            return boost::multiprecision::pow(v, exponent);
        }
    }

    /* Create an ExpMod operation where base, exp and mod are of size 'bits'
     * and base^exp%mod == 0.
     *
     * To find certain modexp reduction bugs such as:
     * https://boringssl.googlesource.com/boringssl/+/13c9d5c69d04485a7a8840c12185c832026c8315
     * https://boringssl.googlesource.com/boringssl/+/801a801024febe1a33add5ddaa719e257d97aba5
     */
    static std::optional<nlohmann::json> generate_exp_mod_is_0(const size_t bits)
    {
        CF_ASSERT(bits > 0, "Bits must be non-zero");

        /* For some reason this crashes with high optimization */
        /*
        const auto min = cpp_int(1) << (bits - 1);
        const auto max = (cpp_int(1) << bits) - 1;
        */

        auto min = cpp_int(1);
        min <<= (bits - 1);

        auto max = cpp_int(1);
        max <<= bits;
        max--;

        /* Create random base/exponent */
        const cpp_int BE = uniform_int_distribution<cpp_int>(min, max)(mt);

        /* Compute some prime factors of base/exponent */
        const auto factors = prime_factors(BE);
        if ( factors.empty() ) {
            return std::nullopt;
        }

        /* Pick two random prime factors */
        const auto P1 = cpp_int(factors[mt() % factors.size()]);
        const auto P2 = factors[mt() % factors.size()];

        /* I = P1^[0..P2] */
        const cpp_int I = pow(P1, mt() % (P2+1));

        /* Any J = P2^[0..I] would yield a valid modulus.
         *
         * However, we want I*J to not exceed the bitsize.
         * Therefore, compute the max J.
         */
        const cpp_int maxJ = max / I;

        //assert(I * maxJ <= max);

        /* Compute the max exponent such that
         * J = P2^exp does not exceed the bitsize.
         */
        const size_t maxJExp = log(maxJ, P2);

        const cpp_int J = pow(cpp_int(P2), maxJExp);

        const cpp_int M = I * J;

        //assert(M <= max);
        //assert(powm(BE, BE, M) == 0);

        return to_json(BE, BE, M);
    }

    /* For all odd values base, pow(base, base*mul, be+1) == base) where mul is any odd value. */
    static std::optional<nlohmann::json> generate_exp_mod_is_odd_base_1(const cpp_int& B) {
        if ( !is_odd(B) ) {
            return std::nullopt;
        }

        cpp_int E = B;
        if ( !multiply_random(E, true) ) {
            return std::nullopt;
        }

        const cpp_int M = B + 1;

        //assert(powm(B, E, M) == B);

        return to_json(B, E, M);
    }

    /* For all odd values base, pow(base, base*mul, base*2) == base) where mul is any positive integer. */
    static std::optional<nlohmann::json> generate_exp_mod_is_odd_base_2(const cpp_int& B) {
        if ( !is_odd(B) ) {
            return std::nullopt;
        }

        cpp_int E = B;
        if ( !multiply_random(E) ) {
            return std::nullopt;
        }

        const cpp_int M = B * 2;

        //assert(powm(B, E, M) == B);

        return to_json(B, E, M);
    }

    /* For all even values base >= 4, pow(base, base*mul, base*2-2) == base) where mul is any positive integer. */
    static std::optional<nlohmann::json> generate_exp_mod_is_even_base_1(const cpp_int& B) {
        if ( !is_even(B) ) {
            return std::nullopt;
        }
        if ( B < 4 ) {
            return std::nullopt;
        }

        cpp_int E = B;
        if ( !multiply_random(E) ) {
            return std::nullopt;
        }

        const cpp_int M = B * 2 - 2;

        //assert(powm(B, E, M) == B);

        return to_json(B, E, M);
    }

    /* For all prime values me > base, pow(base, me, me) == base). */
    static std::optional<nlohmann::json> generate_exp_mod_is_base_1(const cpp_int& B) {
        const cpp_int p = get_prime();

        if ( B <= p ) {
            return std::nullopt;
        }

        const cpp_int E = p;
        const cpp_int M = p;

        /* This only holds for prime p */
        //assert(powm(B, E, M) == B);

        return to_json(B, E, M);
    }

    /* For all prime values p and any positive e, pow(p+1, e, (p+1)*p) == p+1. */
    static std::optional<nlohmann::json> generate_exp_mod_is_base_2(void) {
        const cpp_int p = get_prime();

        if ( p < 3 ) {
            return std::nullopt;
        }

        const cpp_int B = p + 1;
        cpp_int E = 1;
        if ( !multiply_random(E) ) {
            return std::nullopt;
        }
        cpp_int M = p + 1;
        if ( !multiply(M, p) ) {
            return std::nullopt;
        }

        /* This only holds for prime p */
        //assert(powm(B, E, M) == B);

        return to_json(B, E, M);
    }

    /* For all odd values exp, pow(exp*mul, exp, exp*2) == exp) where mul is any odd integer. */
    static std::optional<nlohmann::json> generate_exp_mod_is_odd_exp_1(const cpp_int& E) {
        if ( !is_odd(E) ) {
            return std::nullopt;
        }

        cpp_int B = E;
        if ( !multiply_random(B, true) ) {
            return std::nullopt;
        }
        const cpp_int M = E * 2;

        //assert(powm(B, E, M) == E);

        return to_json(B, E, M);
    }

    /* 1. Let p be a prime such that p*2-1 >= v.
     * 2. Let exp = p*2-1.
     * 3. Let base = exp + (exp * (exp - v)).
     * 4. Let mod = exp + 1.
     * 5. Let k be any positive integer.
     *
     * Now pow(base, exp**k, mod) == v.
     */
    static std::optional<nlohmann::json> generate_exp_mod_is_v_1(const cpp_int& v) {
        /* Step 1 */
        const cpp_int p = get_prime();
        if ( p < 1 ) {
            return std::nullopt;
        }

        /* Step 2 */
        const cpp_int E = 2 * p - 1;
        if ( E > max() || E < v ) {
            return std::nullopt;
        }

        /* Step 3 */
        cpp_int B = E;
        {
            const cpp_int delta = E - v + 1;
            /* B *= delta */
            if ( !multiply(B, delta) ) {
                return std::nullopt;
            }
        }

        /* Step 4 */
        const cpp_int M = E + 1;

        /* TODO exponentiate exp */

        /* This only holds for prime p */
        //assert(powm(B, E, M) == v);

        return to_json(B, E, M);
    }

    /* 1. Let p be a prime such that p-1 >= v.
     * 2. Let exp = p-1.
     * 3. Let base = exp + (exp * (exp - v)).
     * 4. Let mod = exp + 1.
     * 5. Let k be any positive integer.
     *
     * Now pow(base, (exp*k)+1, mod) == v.
     */
    static std::optional<nlohmann::json> generate_exp_mod_is_v_2(const cpp_int& v) {
        /* Step 1 */
        const cpp_int p = get_prime();
        if ( p < 1 ) {
            return std::nullopt;
        }

        /* Step 2 */
        cpp_int E = p - 1;
        if ( E > max() || E < v ) {
            return std::nullopt;
        }

        /* Step 3 */
        cpp_int B = E;
        {
            const cpp_int delta = E - v + 1;
            /* B *= delta */
            if ( !multiply(B, delta) ) {
                return std::nullopt;
            }
        }

        /* Step 4 */
        const cpp_int M = E + 1;

        /* E = E*K+1 */
        if ( !multiply_random(E) ) {
            return std::nullopt;
        }
        E++;

        /* This only holds for prime p */
        //assert(powm(B, E, M) == v);

        return to_json(B, E, M);
    }

    std::optional<nlohmann::json> generate_exp_mod(const std::string& _result) {
        const uint8_t which = PRNG() % 3;
        if ( which == 0 ) {
            static const std::array<size_t, 6> bitsizes{256, 512, 1024, 2048, 4096, 8192};

            return generate_exp_mod_is_0(bitsizes[PRNG() % bitsizes.size()]);
        } else if ( which == 1 ) {
            const cpp_int result = cpp_int(_result);

            const uint8_t which = PRNG() % 2;

            if ( which == 0 ) {
                return generate_exp_mod_is_v_1(result);
            } else if ( which == 1 ) {
                return generate_exp_mod_is_v_2(result);
            } else {
                CF_UNREACHABLE();
            }
        } else if ( which == 2 ) {
            const cpp_int result = cpp_int(_result);

            if ( is_odd(result) ) {
                const uint8_t which = PRNG() % 5;

                if ( which == 0 ) {
                    return generate_exp_mod_is_odd_base_1(result);
                } else if ( which == 1 ) {
                    return generate_exp_mod_is_odd_base_2(result);
                } else if ( which == 2 ) {
                    return generate_exp_mod_is_odd_exp_1(result);
                } else if ( which == 3 ) {
                    return generate_exp_mod_is_base_1(result);
                } else if ( which == 4 ) {
                    return generate_exp_mod_is_base_2();
                } else {
                    CF_UNREACHABLE();
                }
            } else {
                const uint8_t which = PRNG() % 3;

                if ( which == 0 ) {
                    return generate_exp_mod_is_even_base_1(result);
                } else if ( which == 1 ) {
                    return generate_exp_mod_is_base_1(result);
                } else if ( which == 2 ) {
                    return generate_exp_mod_is_base_2();
                } else {
                    CF_UNREACHABLE();
                }
            }
        } else {
            CF_UNREACHABLE();
        }
    }
} /* ExpModGenerator */
} /* mutator */
} /* cryptofuzz */
