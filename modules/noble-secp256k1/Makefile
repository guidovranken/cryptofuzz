all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
noble-secp256k1.bytecode : header.js harness.js ids.js
	test $(LIBFUZZER_JS_PATH)
	test $(NOBLE_SECP256K1_PATH)
	rm -rf noble-secp256k1.bytecode
	cat header.js $(NOBLE_SECP256K1_PATH) ids.js crypto-js/core.js crypto-js/x64-core.js crypto-js/sha256.js crypto-js/hmac.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js noble-secp256k1.bytecode
noble-secp256k1.bytecode.h : noble-secp256k1.bytecode
	xxd -i noble-secp256k1.bytecode >noble-secp256k1.bytecode.h
module.o: module.cpp module.h noble-secp256k1.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a combined.js ids.js generate_ids noble-secp256k1.bytecode noble-secp256k1.bytecode.h
