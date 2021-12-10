#include "module.h"
#include <cryptofuzz/util.h>
#include <fuzzing/datasource/id.hpp>
#include <libdivide.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <limits>

namespace cryptofuzz {
namespace module {

libdivide::libdivide(void) :
    Module("libdivide") { }

namespace libdivide_detail {
    template <class T, class Divider>
        std::optional<component::Bignum> Div(operation::BignumCalc& op) {
            std::optional<component::Bignum> ret = std::nullopt;

            T bn0;
            T bn1;

            try {
                bn0 = boost::lexical_cast<T>(op.bn0.ToTrimmedString());
                bn1 = boost::lexical_cast<T>(op.bn1.ToTrimmedString());
            } catch ( const boost::bad_lexical_cast &e ) {
                goto end;
            }

            CF_CHECK_NE(bn1, 0);

            {
                Divider d(bn1);
                const auto res = bn0 / d;
                ret = std::to_string(res);
            }

end:
            return ret;
        }
}

std::optional<component::Bignum> libdivide::OpBignumCalc(operation::BignumCalc& op) {
    if ( !op.calcOp.Is(CF_CALCOP("Div(A,B)")) ) {
        return std::nullopt;
    }
    Datasource ds(op.modifier.GetPtr(), op.modifier.GetSize());

    uint8_t type;
    try {
        type = ds.Get<uint8_t>();
    } catch ( fuzzing::datasource::Datasource::OutOfData ) { }

    switch ( type ) {
        case    0:
            return libdivide_detail::Div<int16_t, ::libdivide::divider<int16_t>>(op);
        case    1:
            return libdivide_detail::Div<uint16_t, ::libdivide::divider<uint16_t>>(op);
        case    2:
            return libdivide_detail::Div<int32_t, ::libdivide::divider<int32_t>>(op);
        case    3:
            return libdivide_detail::Div<uint32_t, ::libdivide::divider<uint32_t>>(op);
        case    4:
            return libdivide_detail::Div<int64_t, ::libdivide::divider<int64_t>>(op);
        case    5:
            return libdivide_detail::Div<uint64_t, ::libdivide::divider<uint64_t>>(op);

        case    6:
            CF_CHECK_NE(op.bn1.ToTrimmedString(), "1");
            return libdivide_detail::Div<int16_t, ::libdivide::branchfree_divider<int16_t>>(op);
        case    7:
            CF_CHECK_NE(op.bn1.ToTrimmedString(), "1");
            return libdivide_detail::Div<uint16_t, ::libdivide::branchfree_divider<uint16_t>>(op);
        case    8:
            CF_CHECK_NE(op.bn1.ToTrimmedString(), "1");
            return libdivide_detail::Div<int32_t, ::libdivide::branchfree_divider<int32_t>>(op);
        case    9:
            CF_CHECK_NE(op.bn1.ToTrimmedString(), "1");
            return libdivide_detail::Div<uint32_t, ::libdivide::branchfree_divider<uint32_t>>(op);
        case    10:
            CF_CHECK_NE(op.bn1.ToTrimmedString(), "1");
            return libdivide_detail::Div<int64_t, ::libdivide::branchfree_divider<int64_t>>(op);
        case    11:
            CF_CHECK_NE(op.bn1.ToTrimmedString(), "1");
            return libdivide_detail::Div<uint64_t, ::libdivide::branchfree_divider<uint64_t>>(op);
    }

end:
    return std::nullopt;
}

} /* namespace module */
} /* namespace cryptofuzz */
