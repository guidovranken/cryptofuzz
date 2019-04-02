#ifndef FUZZING_MEMORY_HPP
#define FUZZING_MEMORY_HPP

#include <stdio.h>
#include <optional>

namespace fuzzing {
namespace memory {

void memory_test_msan(const void* data, const size_t size);

#ifndef FUZZING_HEADERS_NO_IMPL
#if ASAN == 1
extern "C" void *__asan_region_is_poisoned(const void *beg, size_t size);
#endif

void memory_test_asan(const void* data, const size_t size)
{
    (void)data;
    (void)size;

#if ASAN == 1
    if ( __asan_region_is_poisoned(data, size) != NULL ) {
        abort();
    }
#endif
}

void memory_test_msan(const void* data, const size_t size)
{
    (void)data;
    (void)size;

#if MSAN == 1
    FILE* fp = fopen("/dev/null", "wb");
    if ( fp == nullptr ) {
        abort();
    }
    fwrite(data, size, 1, fp);
    fclose(fp);
#endif
}

void memory_test(const void* data, const size_t size)
{
    memory_test_asan(data, size);
    memory_test_msan(data, size);
}

template <class T>
void memory_test(const T& t)
{
    (void)t;
}

template <>
void memory_test(const std::string& s)
{
    (void)s;

#if MSAN == 1
    memory_test(s.data(), s.size());
#endif
}

#endif

} /* namespace memory */
} /* namespace fuzzing */

#endif
