all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

ifneq (,$(findstring fsanitize=memory,$(CFLAGS)))
	CXXFLAGS += -DSANITIZER_MSAN
endif

module.a: module.o
	test $(OPENSSL_LIBCRYPTO_A_PATH)
	bash ../link.sh module.a $(OPENSSL_LIBCRYPTO_A_PATH)
	ranlib module.a
module.o: module.cpp module.h module_internal.h
	test $(OPENSSL_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
