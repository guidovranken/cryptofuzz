#include <cryptofuzz/components.h>
#include <cryptofuzz/operations.h>

extern "C" {
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/ecc.h>
}

namespace cryptofuzz {
namespace module {
namespace wolfCrypt_bignum {

class Bignum {
    private:
        mp_int* mp = nullptr;
        Datasource& ds;
        const bool noFree = false;
    public:

        Bignum(Datasource& ds) :
            ds(ds) {
            mp = (mp_int*)util::malloc(sizeof(mp_int));
            if ( mp_init(mp) != MP_OKAY ) {
                util::free(mp);
                throw std::exception();
            }
        }

        Bignum(mp_int* mp, Datasource& ds) :
            mp(mp),
            ds(ds),
            noFree(true)
        { }

        ~Bignum() {
            if ( noFree == false ) {
                /* noret */ mp_clear(mp);
                util::free(mp);
            }
        }

        Bignum(const Bignum& other) :
            ds(other.ds) {
            mp = (mp_int*)util::malloc(sizeof(mp_int));
            if ( mp_init(mp) != MP_OKAY ) {
                util::free(mp);
                throw std::exception();
            }
            if ( mp_copy(other.mp, mp) != MP_OKAY ) {
                util::free(mp);
                throw std::exception();
            }
        }

        Bignum(const Bignum&& other) :
            ds(other.ds) {
            mp = (mp_int*)util::malloc(sizeof(mp_int));
            if ( mp_init(mp) != MP_OKAY ) {
                util::free(mp);
                throw std::exception();
            }
            if ( mp_copy(other.mp, mp) != MP_OKAY ) {
                util::free(mp);
                throw std::exception();
            }
        }

        bool Set(const std::string s) {
            bool ret = false;

            bool hex = false;
            try {
                hex = ds.Get<bool>();
            } catch ( ... ) { }

#if defined(WOLFSSL_SP_MATH)
            hex = true;
#endif

            if ( hex == true ) {
                const auto asDec = util::DecToHex(s);
                CF_CHECK_EQ(mp_read_radix(mp, asDec.c_str(), 16), MP_OKAY);
            } else {
                CF_CHECK_EQ(mp_read_radix(mp, s.c_str(), 10), MP_OKAY);
            }

            ret = true;
end:
            return ret;
        }

        mp_int* GetPtr(void) {
            return mp;
        }

        std::optional<uint64_t> AsUint64(void) const {
            std::optional<uint64_t> ret = std::nullopt;
            uint64_t v = 0;

#if !defined(WOLFSSL_SP_MATH)
            CF_CHECK_EQ(mp_isneg(mp), 0);
#endif
            CF_CHECK_LTE(mp_count_bits(mp), (int)(sizeof(v) * 8));
            CF_CHECK_EQ(mp_to_unsigned_bin_len(mp, (uint8_t*)&v, sizeof(v)), MP_OKAY);
            v =
                ((v & 0xFF00000000000000) >> 56) |
                ((v & 0x00FF000000000000) >> 40) |
                ((v & 0x0000FF0000000000) >> 24) |
                ((v & 0x000000FF00000000) >>  8) |
                ((v & 0x00000000FF000000) <<  8) |
                ((v & 0x0000000000FF0000) << 24) |
                ((v & 0x000000000000FF00) << 40) |
                ((v & 0x00000000000000FF) << 56);

            ret = v;
end:
            return ret;
        }

        template <class T>
        std::optional<T> AsUnsigned(void) const {
            std::optional<T> ret = std::nullopt;
            T v2;

            auto v = AsUint64();
            CF_CHECK_NE(v, std::nullopt);

            v2 = *v;
            CF_CHECK_EQ(v2, *v);

            ret = v2;

end:
            return ret;
        }

        std::optional<std::string> ToDecString(void) {
            std::optional<std::string> ret = std::nullopt;
            char* str = nullptr;

            str = (char*)malloc(8192);

#if defined(WOLFSSL_SP_MATH)
            CF_CHECK_EQ(mp_tohex(mp, str), MP_OKAY);
            ret = { util::HexToDec(str) };
#else
            bool hex = false;
            try {
                hex = ds.Get<bool>();
            } catch ( ... ) { }

            if ( hex == true ) {
                CF_CHECK_EQ(mp_tohex(mp, str), MP_OKAY);
                ret = { util::HexToDec(str) };
            } else {
                CF_CHECK_EQ(mp_toradix(mp, str, 10), MP_OKAY);
                ret = std::string(str);
            }
#endif

end:
            free(str);

            return ret;
        }

        std::optional<component::Bignum> ToComponentBignum(void) {
            std::optional<component::Bignum> ret = std::nullopt;

            auto str = ToDecString();
            CF_CHECK_NE(str, std::nullopt);
            ret = { str };
end:
            return ret;
        }
};

class Operation {
    public:
        virtual bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const = 0;
        virtual ~Operation() { }
};

class Add : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Sub : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Mul : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Div : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class ExpMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Sqr : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class GCD : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class InvMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Cmp : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Abs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Neg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class RShift : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class LShift1 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsNeg : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsEq : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsZero : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsOne : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class MulMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class AddMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class SubMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class SqrMod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Bit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class CmpAbs : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class SetBit : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class LCM : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Mod : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsEven : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class IsOdd : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class MSB : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class NumBits : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Set : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Jacobi : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class Exp2 : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

class NumLSZeroBits : public Operation {
    public:
        bool Run(Datasource& ds, Bignum& res, std::vector<Bignum>& bn) const override;
};

} /* namespace wolfCrypt_bignum */
} /* namespace module */
} /* namespace cryptofuzz */
