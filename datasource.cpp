#ifdef FUZZING_HEADERS_NO_IMPL
#undef FUZZING_HEADERS_NO_IMPL
#endif
#include <fuzzing/datasource/datasource.hpp>

/* Explicit instantiation of templated method */
template uint64_t fuzzing::datasource::Base::Get<uint64_t>(const uint64_t id);
