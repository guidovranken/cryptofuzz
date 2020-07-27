all: module.a

CXXFLAGS += -Wall -Wextra -Wno-deprecated-declarations -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

ifneq (,$(findstring fsanitize=memory,$(CFLAGS)))
	CXXFLAGS += -DSANITIZER_MSAN
endif

module.a: module.o bn_ops.o module_internal.o evp_encrypt.o
	test $(OPENSSL_LIBCRYPTO_A_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(OPENSSL_LIBCRYPTO_A_PATH)
	ar rcs module.a module.o bn_ops.o module_internal.o evp_encrypt.o tmp/*
	ranlib module.a
bn_ops.o : bn_ops.cpp bn_ops.h
	$(CXX) $(CXXFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c bn_ops.cpp -o bn_ops.o
evp_encrypt.o : evp_encrypt.cpp evp_encrypt.h module_internal.h
	$(CXX) $(CXXFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c evp_encrypt.cpp -o evp_encrypt.o
module_internal.o : module_internal.cpp module_internal.h
	$(CXX) $(CXXFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c module_internal.cpp -o module_internal.o
module.o: module.cpp module.h module_internal.h bn_ops.h
	test $(OPENSSL_INCLUDE_PATH)
	$(CXX) $(CXXFLAGS) -I $(OPENSSL_INCLUDE_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
