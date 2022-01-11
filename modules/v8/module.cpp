#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>

#include <src/bigint/bigint-internal.h>

namespace cryptofuzz {
namespace module {

V8::V8(void) :
    Module("V8") { }

namespace V8_detail {
    std::optional<v8::bigint::ScratchDigits> ToDigits(v8::bigint::Processor* processor, const std::string& bn) {
        constexpr int kMaxDigits = 1 << 20;

        v8::bigint::FromStringAccumulator accumulator(kMaxDigits);
        accumulator.Parse(bn.data(), bn.data() + bn.size(), 10);

        v8::bigint::ScratchDigits digits(accumulator.ResultLength());

        CF_CHECK_EQ(processor->FromString(digits, &accumulator), v8::bigint::Status::kOk);

        return digits;

end:
        return std::nullopt;
    }

    std::optional<v8::bigint::ScratchDigits> ToDigits(v8::bigint::Processor* processor, const component::Bignum& bn) {
        const auto s = bn.ToTrimmedString();

        /* Heap overflow if input string has leading zeroes */
        //const auto s = bn.ToString();

        return ToDigits(processor, s);
    }
}

std::optional<component::Bignum> V8::OpBignumCalc(operation::BignumCalc& op) {
    using namespace v8::bigint;
    std::optional<component::Bignum> ret = std::nullopt;
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    char* out = nullptr;
    int out_length = 80001; /* 2 * max input len + 1 */
    auto processor = Processor::New(new Platform());
    std::optional<ScratchDigits> bn0, bn1;

    CF_CHECK_NE(bn0 = V8_detail::ToDigits(processor, op.bn0), std::nullopt);
    CF_CHECK_NE(bn1 = V8_detail::ToDigits(processor, op.bn1), std::nullopt);

    out = (char*)util::malloc(out_length);

    {
        std::unique_ptr<ScratchDigits> result = nullptr;

        switch ( op.calcOp.Get() ) {
            case    CF_CALCOP("Add(A,B)"):
                result = std::make_unique<ScratchDigits>(AddResultLength(bn0->len(), bn1->len()));
                CF_NORET(Add(*result, *bn0, *bn1));
                break;
            case    CF_CALCOP("Sub(A,B)"):
                CF_CHECK_GT(bn0->len(), bn1->len());
                result = std::make_unique<ScratchDigits>(SubtractResultLength(bn0->len(), bn1->len()));
                CF_NORET(Subtract(*result, *bn0, *bn1));
                break;
            case    CF_CALCOP("Mul(A,B)"):
                {
                    result = std::make_unique<ScratchDigits>(MultiplyResultLength(*bn0, *bn1));

                    uint8_t which = 0;
                    try {
                        which = ds.Get<uint8_t>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                    switch ( which ) {
                        case    0:
                            CF_CHECK_EQ(processor->Multiply(*result, *bn0, *bn1), Status::kOk);
                            break;
                        case    1:
                            CF_NORET(static_cast<ProcessorImpl*>(processor)->Multiply(*result, *bn0, *bn1));
                            break;
                        /* Heap overflow */
#if 0
                        case    2:
                            CF_NORET(static_cast<ProcessorImpl*>(processor)->MultiplyKaratsuba(*result, *bn0, *bn1));
                            break;
#endif
                        case    3:
                            CF_NORET(static_cast<ProcessorImpl*>(processor)->MultiplyToomCook(*result, *bn0, *bn1));
                            break;
                        /* Heap overflow */
#if 0
                        case    4:
                            CF_NORET(static_cast<ProcessorImpl*>(processor)->MultiplyFFT(*result, *bn0, *bn1));
                            break;
#endif
                        default:
                            goto end;
                    }
                }
                break;
            case    CF_CALCOP("Div(A,B)"):
                {
                    CF_CHECK_NE(op.bn1.ToTrimmedString(), "0");
                    const auto len = DivideResultLength(*bn0, *bn1);
                    CF_CHECK_GTE(len, 0);
                    result = std::make_unique<ScratchDigits>(len);

                    auto remainder = std::make_unique<ScratchDigits>(bn1->len());

                    uint8_t which = 0;
                    try {
                        which = ds.Get<uint8_t>();
                    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

                    switch ( which % 4 ) {
                        case    0:
                            CF_CHECK_EQ(processor->Divide(*result, *bn0, *bn1), Status::kOk);
                            break;
                        case    1:
                            /* Heap overflow */
#if 0
                            CF_NORET(static_cast<ProcessorImpl*>(processor)->DivideSchoolbook(*result, *remainder, *bn0, *bn1));
                            break;
#endif
                            goto end;
                        case    2:
                            /* Incorrect result */
#if 0
                            CF_NORET(static_cast<ProcessorImpl*>(processor)->DivideBurnikelZiegler(*result, *remainder, *bn0, *bn1));
#endif
                            goto end;
                            break;
                        case    3:
                            /* Heap overflow */
#if 0
                            CF_NORET(static_cast<ProcessorImpl*>(processor)->DivideBarrett(*result, *remainder, *bn0, *bn1));
#endif
                            goto end;
                            break;
                        default:
                            goto end;
                    }
                }
                break;
            case    CF_CALCOP("Mod(A,B)"):
                /* Heap overflow if this check is removed */
                CF_CHECK_NE(op.bn1.ToTrimmedString(), "0");

                /* Incorrect result if this check is removed */
                CF_CHECK_GTE(Compare(*bn0, *bn1), 0);

                result = std::make_unique<ScratchDigits>(ModuloResultLength(*bn1));
                CF_CHECK_EQ(processor->Modulo(*result, *bn0, *bn1), Status::kOk);
                break;
            case    CF_CALCOP("Cmp(A,B)"):
                {
                    auto cmp = Compare(*bn0, *bn1);

                    if ( cmp < 0 ) {
                        cmp = -1;
                    } else if ( cmp > 0 ) {
                        cmp = 1;
                    }

                    ret = std::to_string(cmp);
                }
                goto end;
                break;
            case    CF_CALCOP("And(A,B)"):
                result = std::make_unique<ScratchDigits>(BitwiseAnd_PosPos_ResultLength(bn0->len(), bn1->len()));
                CF_NORET(BitwiseAnd_PosPos(*result, *bn0, *bn1));
                break;
            case    CF_CALCOP("Or(A,B)"):
                result = std::make_unique<ScratchDigits>(BitwiseOrResultLength(bn0->len(), bn1->len()));
                CF_NORET(BitwiseOr_PosPos(*result, *bn0, *bn1));
                break;
            case    CF_CALCOP("Xor(A,B)"):
                result = std::make_unique<ScratchDigits>(BitwiseXor_PosPos_ResultLength(bn0->len(), bn1->len()));
                CF_NORET(BitwiseXor_PosPos(*result, *bn0, *bn1));
                break;
            default:
                goto end;
        }

        CF_CHECK_EQ(processor->ToString(out, &out_length, *result, 10, false), Status::kOk);
    }

    {
        auto s = std::string(out, out_length);

        if ( s == "" ) {
            s = "0";
        }

        ret = s;
    }

end:
    util::free(out);
    processor->Destroy();

    return ret;
}

} /* namespace module */
} /* namespace cryptofuzz */
