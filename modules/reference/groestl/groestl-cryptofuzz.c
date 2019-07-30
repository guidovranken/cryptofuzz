#include "Groestl-ref.h"
#include "groestl-cryptofuzz.h"

void* groestl_init(const int hashbitLen) {
    hashState* ctx = malloc(sizeof(hashState));
    if ( Init(ctx, hashbitLen) != SUCCESS ) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

bool groestl_update(void* ctx, const uint8_t* data, const size_t size) {
    return Update((hashState*)ctx, data, size * 8) == SUCCESS;
}

bool groestl_final(void* ctx, uint8_t* out) {
    return Final((hashState*)ctx, out) == SUCCESS;
}

void groestl_free(void* ctx) {
    free(ctx);
}
