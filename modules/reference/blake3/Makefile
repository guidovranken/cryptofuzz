BARE_CFLAGS = -O3 -Wall -Wextra -std=c11 -pedantic
CFLAGS += -O3 -Wall -Wextra -std=c11 -pedantic

all: libblake3.a

libblake3.a : blake3.o blake3_dispatch.o blake3_portable.o blake3_sse41.o blake3_avx2.o blake3_avx512.o
	ar rcs libblake3.a *.o

blake3.o : blake3.c
	$(CC) $(CFLAGS) -c $^ -o $@

blake3_dispatch.o : blake3_dispatch.c
	$(CC) $(CFLAGS) -c $^ -o $@

blake3_portable.o : blake3_portable.c
	$(CC) $(CFLAGS) -c $^ -o $@

blake3_sse41.o: blake3_sse41.c
	$(CC) $(BASE_CFLAGS) -c $^ -o $@ -msse4.1 -D BLAKE3_USE_SSE41

blake3_avx2.o: blake3_avx2.c # blake3_sse41.c
	$(CC) $(BASE_CFLAGS) -c $^ -o $@ -mavx2 -D BLAKE3_USE_SSE41 -D BLAKE3_USE_AVX2

blake3_avx512.o: blake3_avx512.c
	$(CC) $(BASE_CFLAGS) -c $^ -o $@ -mavx512f -mavx512vl -D BLAKE3_USE_SSE41 -D BLAKE3_USE_AVX2 -D BLAKE3_USE_AVX512

blake3_neon.o: blake3_neon.c
	$(CC) $(CFLAGS) -c $^ -o $@ -D BLAKE3_USE_NEON

clean: 
	rm -f $(NAME) *.o
