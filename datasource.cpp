#ifdef FUZZING_HEADERS_NO_IMPL
#undef FUZZING_HEADERS_NO_IMPL
#endif
#include <fuzzing/datasource/datasource.hpp>

/* Explicit instantiation of templated methods */
template uint64_t fuzzing::datasource::Base::Get<uint64_t>(const uint64_t id);
template uint32_t fuzzing::datasource::Base::Get<uint32_t>(const uint64_t id);
template uint8_t fuzzing::datasource::Base::Get<uint8_t>(const uint64_t id);
