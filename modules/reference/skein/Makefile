all : libskein.a

libskein.a : SHA3api_ref.c skein_block.c skein.c skein_debug.c brg_endian.h brg_types.h SHA3api_ref.h skein_debug.h skein.h skein_port.h
	$(CC) $(CFLAGS) -c SHA3api_ref.c skein_block.c skein.c skein_debug.c
	ar rcs libskein.a *.o 

clean:
	rm -rf *.o
	rm -rf *.a
