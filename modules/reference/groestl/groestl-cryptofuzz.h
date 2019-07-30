#include <stdbool.h>
void* groestl_init(const int hashbitLen);
bool groestl_update(void* ctx, const uint8_t* data, const size_t size);
bool groestl_final(void* ctx, uint8_t* out);
void groestl_free(void* ctx);
