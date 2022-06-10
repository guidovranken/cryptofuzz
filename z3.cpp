#if defined(CRYPTOFUZZ_HAVE_Z3)

#include "z3++.h"
#include <optional>
#include <string>
#include <map>
#include <vector>
#include "_z3.h"
#include <fuzzing/datasource/datasource.hpp>
#include <fuzzing/datasource/id.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <cryptofuzz/util.h>
#include <cryptofuzz/repository.h>
#include "config.h"

bool getBool(void);
std::string getBignum(bool mustBePositive = false);
uint32_t PRNG(void);

namespace cryptofuzz {
namespace Z3 {
    //static const std::string max(cryptofuzz::config::kMaxBignumSize, '9');
    class Solver {
        private:
            std::vector<z3::expr> constraints;
            z3::context ctx;
            bool terminated = false;
            bool haveBitvector = false;
        protected:
            std::map<std::string, z3::expr> dynExprs;
            std::map<std::string, z3::expr> statExprs;

            std::string ParseInt(const std::string v) {
                if ( v.size() >= 2 && v[0] == '#' && v[1] == 'x' ) {
                    return util::HexToDec(v.substr(2));
                } else {
                    return v;
                }
            }
            const z3::expr& AddDynamic(const std::string name, const bool bitvector = false) {
                if ( bitvector == false ) {
                    dynExprs.emplace(name, ctx.int_const(name.c_str()));
                } else {
                    dynExprs.emplace(name, ctx.bv_const(name.c_str(), 256));
                    haveBitvector = true;
                }
                const z3::expr& expr = dynExprs.at(name);
                if ( cryptofuzz::config::kNegativeIntegers == false ) {
                    //AddConstraint(expr >= 0);
                }
                //AddConstraint(expr <= AddStatic("Max", max));
                return expr;
            }
            const z3::expr& AddDynamicDivisor(const std::string name) {
                const auto& expr = AddDynamic(name);
                NotZero(expr);
                return expr;
            }
            const z3::expr& AddStatic(const std::string name, const std::string value, const bool bitvector = false) {
                if ( bitvector == false ) {
                    statExprs.emplace(name, ctx.int_val(value.c_str()));
                } else {
                    statExprs.emplace(name, ctx.bv_val(value.c_str(), 256));
                    haveBitvector = true;
                }
                return statExprs.at(name);
            }
            void AddConstraint(const z3::expr expr) {
                constraints.emplace_back(expr);
            }
            void AddOptionalConstraint(const z3::expr expr) {
                if ( getBool() ) {
                    constraints.emplace_back(expr);
                }
            }
            void NotZero(const z3::expr& expr) {
                AddConstraint(expr != 0);
            }
            void AddRandomConstraint(void) {
                if ( haveBitvector == true ) {
                    return;
                }

                const uint8_t r = PRNG() % 3;

                if ( r == 0 ) {
                    return;
                }

                auto it = dynExprs.cbegin();
                std::advance(it, PRNG() % dynExprs.size());
                const auto& l = AddStatic("L", getBignum());
                const auto& v = dynExprs.at(it->first);

                if ( r == 1 ) {
                    AddConstraint(v < l);
                } else if ( r == 2 ) {
                    AddConstraint(v > l);
                } else if ( r == 3 ) {
                    AddConstraint(v == l);
                }
            }
        public:
            Solver(void) { };
            virtual ~Solver() { }
            std::optional<std::map<std::string, std::string>> Solve(void) {
                assert(!terminated);
                terminated = true;

                std::map<std::string, std::string> ret;

                AddRandomConstraint();
                AddRandomConstraint();

                z3::solver s(ctx);

#if 1
#define TIMEOUT_MS 500
                z3::set_param("timeout", TIMEOUT_MS);
                z3::params params(ctx);
                params.set("timeout", static_cast<unsigned>(TIMEOUT_MS));
                s.set(params);
#undef TIMEOUT_MS
#endif

                for (const auto& c : constraints) {
                    s.add(c);
                }

                if ( s.check() != z3::check_result::sat ) {
                    return std::nullopt;
                }

                z3::model m = s.get_model();

                for (unsigned i = 0; i < m.size(); i++) {
                    z3::func_decl v = m[static_cast<int>(i)];
                    const std::string key = v.name().str();
                    for (const auto& expr : dynExprs) {
                        if ( expr.first == key ) {
                            ret[key] = ParseInt(m.get_const_interp(v).to_string());
                            break;
                        }
                    }
                }

                return ret;
            }
    };

    class Add : public Solver {
        public:
            Add(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto R = AddStatic("R", r);
                AddConstraint((A + B) == R);
            }
    };
    class AddMod : public Solver {
        public:
            AddMod(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto C = AddDynamicDivisor("C");
                const auto R = AddStatic("R", r);
                AddConstraint((A + B) % C == R);
                AddOptionalConstraint((A + B) > R);
            }
    };
    class AddMul : public Solver {
        public:
            AddMul(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto C = AddDynamic("C");
                const auto R = AddStatic("R", r);
                AddConstraint((A + B) * C == R);
            }
    };
    class Sub : public Solver {
        public:
            Sub(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto R = AddStatic("R", r);
                AddConstraint((A - B) == R);
            }
    };
    class SubMod : public Solver {
        public:
            SubMod(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto C = AddDynamicDivisor("C");
                const auto R = AddStatic("R", r);
                AddConstraint((A - B) % C == R);
                AddOptionalConstraint((A - B) > R);
            }
    };
    class SubMul : public Solver {
        public:
            SubMul(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto C = AddDynamic("C");
                const auto R = AddStatic("R", r);
                AddConstraint((A - B) * C == R);
            }
    };
    class Mul : public Solver {
        public:
            Mul(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto R = AddStatic("R", r);
                AddConstraint(A != 1);
                AddConstraint(B != 1);
                AddConstraint(A * B == R);
            }
    };
    class MulMod : public Solver {
        public:
            MulMod(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto C = AddDynamicDivisor("C");
                const auto R = AddStatic("R", r);
                AddConstraint((A * B) % C == R);
                //AddOptionalConstraint((A * B) > R);
            }
    };
    class MulAdd : public Solver {
        public:
            MulAdd(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto C = AddDynamic("C");
                const auto R = AddStatic("R", r);
                AddConstraint((A * B) + C == R);
            }
    };
    class Div : public Solver {
        public:
            Div(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamicDivisor("B");
                const auto R = AddStatic("R", r);
                AddConstraint(B != 1);
                AddConstraint(A / B == R);
            }
    };
    class MulDiv : public Solver {
        public:
            MulDiv(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamic("B");
                const auto C = AddDynamicDivisor("C");
                const auto R = AddStatic("R", r);
                AddConstraint(A != C);
                AddConstraint(B != C);
                AddOptionalConstraint((A * B) > R);
                AddConstraint((A * B) / C == R);
            }
    };
    using MulDivCeil = MulDiv;
    class Mod : public Solver {
        public:
            Mod(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamicDivisor("B");
                const auto R = AddStatic("R", r);
                AddConstraint(A % B == R);
                AddConstraint(B < A);
            }
    };
    class ModFixed : public Solver {
        public:
            ModFixed(const std::string r, const std::string mod) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto M = AddStatic("M", mod);
                const auto R = AddStatic("R", r);
                AddConstraint(A >= M);
                AddConstraint(A % M == R);
            }
    };
    class Mod_NIST_192 : public ModFixed {
        public:
            Mod_NIST_192(const std::string r) :
                ModFixed(r, "6277101735386680763835789423207666416083908700390324961279")
            { };
    };
    class Mod_NIST_224 : public ModFixed {
        public:
            Mod_NIST_224(const std::string r) :
                ModFixed(r, "26959946667150639794667015087019630673557916260026308143510066298881")
            { };
    };
    class Mod_NIST_256 : public ModFixed {
        public:
            Mod_NIST_256(const std::string r) :
                ModFixed(r, "115792089210356248762697446949407573530086143415290314195533631308867097853951")
            { };
    };
    class Mod_NIST_384 : public ModFixed {
        public:
            Mod_NIST_384(const std::string r) :
                ModFixed(r, "39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319")
            { };
    };
    class Mod_NIST_521 : public ModFixed {
        public:
            Mod_NIST_521(const std::string r) :
                ModFixed(r, "6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151")
            { };
    };
    class Sqr : public Solver {
        public:
            Sqr(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto R = AddStatic("R", r);
                AddConstraint(A * A == R);
            }
    };
    class Sqrt : public Solver {
        public:
            Sqrt(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto X = AddDynamic("X");
                const auto R = AddStatic("R", r);
                AddConstraint((R * R) + X == A);
                AddConstraint(A < ((R+1) * (R+1)));
            }
    };
    class SqrtRem : public Solver {
        public:
            SqrtRem(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto X = AddDynamic("X");
                const auto R = AddStatic("R", r);
                AddConstraint((X * X) + R == A);
                AddConstraint(A < ((X+1) * (X+1)));
            }
    };
    class CbrtRem : public Solver {
        public:
            CbrtRem(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto X = AddDynamic("X");
                const auto R = AddStatic("R", r);
                AddConstraint((X * X * X) + R == A);
                AddConstraint(A < ((X+1) * (X+1) * (X+1)));
            }
    };
    class SqrMod : public Solver {
        public:
            SqrMod(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A");
                const auto B = AddDynamicDivisor("B");
                const auto R = AddStatic("R", r);
                AddConstraint((A * A) % B == R);
            }
    };
    class Or : public Solver {
        public:
            Or(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A", true);
                const auto B = AddDynamic("B", true);
                const auto R = AddStatic("R", r, true);
                AddConstraint((A | B) == R);
            }
    };
    class Xor : public Solver {
        public:
            Xor(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A", true);
                const auto B = AddDynamic("B", true);
                const auto R = AddStatic("R", r, true);
                AddConstraint((A ^ B) == R);
            }
    };
    class And : public Solver {
        public:
            And(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A", true);
                const auto B = AddDynamic("B", true);
                const auto R = AddStatic("R", r, true);
                AddConstraint((A & B) == R);
            }
    };
    class RShift : public Solver {
        public:
            RShift(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A", true);
                const auto B = AddDynamic("B", true);
                const auto R = AddStatic("R", r, true);
                AddConstraint(z3::ashr(A, B) == R);
            }
    };
    class LShift1 : public Solver {
        public:
            LShift1(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A", true);
                const auto R = AddStatic("R", r, true);
                AddConstraint(z3::shl(A, 1) == R);
            }
    };
    class SetBit : public Solver {
        public:
            SetBit(const std::string r) :
                Solver() {
                const auto A = AddDynamic("A", true);
                const auto B = AddDynamic("B", true);
                const auto R = AddStatic("R", r, true);
                AddConstraint((A | z3::shl(1, B)) == R);
            }
    };

    static bool is_negative(const std::string s) {
        return s.size() && s[0] == '(';
    }
    template <class T, uint64_t Calcop>
    std::optional<nlohmann::json> invoke(const std::string result) {
        T s(result);

        const auto res = s.Solve();

        if ( res == std::nullopt ) {
            return std::nullopt;
        }

        nlohmann::json ret;
        ret["modifier"] = "";
        ret["calcOp"] = Calcop;
        ret["bn1"] = "";
        ret["bn2"] = "";
        ret["bn3"] = "";
        ret["bn4"] = "";

        const size_t NumParams = repository::CalcOpToNumParams(Calcop);

        if ( NumParams >= 1 ) {
            const auto v = res->at("A");
            if ( is_negative(v) ) {
                return std::nullopt;
            }
            ret["bn1"] = v;
        }
        if ( NumParams >= 2 ) {
            const auto v = res->at("B");
            if ( is_negative(v) ) {
                return std::nullopt;
            }
            ret["bn2"] = v;
        }
        if ( NumParams >= 3 ) {
            const auto v = res->at("C");
            if ( is_negative(v) ) {
                return std::nullopt;
            }
            ret["bn3"] = v;
        }

#if 0
        std::cout << "Op: " << repository::CalcOpToString(Calcop) << std::endl;
        std::cout << "R: " << result << std::endl;
        if ( NumParams >= 1 ) {
            std::cout << "A: " << res->at("A") << std::endl;
        }
        if ( NumParams >= 2 ) {
            std::cout << "B: " << res->at("B") << std::endl;
        }
        if ( NumParams >= 3 ) {
            std::cout << "C: " << res->at("C") << std::endl;
        }
        //std::cout << "X: " << res->at("X") << std::endl;
        std::cout << std::endl;
#endif

        return ret;
    }

    std::optional<nlohmann::json> Generate(const uint64_t calcop) {
        boost::multiprecision::cpp_int v(1);
        v <<= (PRNG() % 258) + 1;
        if ( getBool() ) {
            v--;
        }
        const std::string result = v.str();
#if 0
        if ( result.size() > cryptofuzz::config::kMaxBignumSize ) {
            return std::nullopt;
        }
        if ( result == "" || result == "0" || result == "1" ) {
            return std::nullopt;
        }
#endif
#define INVOKE(t, c) case c: return invoke<t, c>(result);
        switch ( calcop ) {
            INVOKE(Z3::Add, CF_CALCOP("Add(A,B)"));
            INVOKE(Z3::AddMod, CF_CALCOP("AddMod(A,B,C)"));
            INVOKE(Z3::AddMul, CF_CALCOP("AddMul(A,B,C)"));
            INVOKE(Z3::Sub, CF_CALCOP("Sub(A,B)"));
            INVOKE(Z3::SubMod, CF_CALCOP("SubMod(A,B,C)"));
            INVOKE(Z3::SubMul, CF_CALCOP("SubMul(A,B,C)"));
            INVOKE(Z3::Mul, CF_CALCOP("Mul(A,B)"));
            INVOKE(Z3::MulMod, CF_CALCOP("MulMod(A,B,C)"));
            INVOKE(Z3::MulAdd, CF_CALCOP("MulAdd(A,B,C)"));
            INVOKE(Z3::MulDiv, CF_CALCOP("MulDiv(A,B,C)"));
            INVOKE(Z3::MulDivCeil, CF_CALCOP("MulDivCeil(A,B,C)"));
            INVOKE(Z3::Div, CF_CALCOP("Div(A,B)"));
            INVOKE(Z3::Mod, CF_CALCOP("Mod(A,B)"));
            INVOKE(Z3::Mod_NIST_192, CF_CALCOP("Mod_NIST_192(A)"));
            INVOKE(Z3::Mod_NIST_224, CF_CALCOP("Mod_NIST_224(A)"));
            INVOKE(Z3::Mod_NIST_256, CF_CALCOP("Mod_NIST_256(A)"));
            INVOKE(Z3::Mod_NIST_384, CF_CALCOP("Mod_NIST_384(A)"));
            INVOKE(Z3::Mod_NIST_521, CF_CALCOP("Mod_NIST_521(A)"));
            //INVOKE(Z3::Sqr, CF_CALCOP("Sqr(A)"));
            INVOKE(Z3::Sqrt, CF_CALCOP("Sqrt(A)"));
            INVOKE(Z3::SqrtRem, CF_CALCOP("SqrtRem(A)"));
            INVOKE(Z3::CbrtRem, CF_CALCOP("CbrtRem(A)"));
            INVOKE(Z3::SqrMod, CF_CALCOP("SqrMod(A,B)"));
            INVOKE(Z3::Or, CF_CALCOP("Or(A,B)"));
            INVOKE(Z3::Xor, CF_CALCOP("Xor(A,B)"));
            INVOKE(Z3::And, CF_CALCOP("And(A,B)"));
            INVOKE(Z3::RShift, CF_CALCOP("RShift(A,B)"));
            INVOKE(Z3::LShift1, CF_CALCOP("LShift1(A)"));
            INVOKE(Z3::SetBit, CF_CALCOP("SetBit(A,B)"));
        }
#undef INVOKE
        return std::nullopt;
    }
}
}

#endif /* CRYPTOFUZZ_HAVE_Z3 */
