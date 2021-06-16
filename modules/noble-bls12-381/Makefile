all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
noble-bls12-381.bytecode : header.js harness.js ids.js
	rm -rf noble-bls12-381.bytecode
	cat header.js $(NOBLE_BLS12_381_PATH) ids.js crypto-js/core.js crypto-js/x64-core.js crypto-js/sha256.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js noble-bls12-381.bytecode
noble-bls12-381.bytecode.h : noble-bls12-381.bytecode
	xxd -i noble-bls12-381.bytecode >noble-bls12-381.bytecode.h
module.o: module.cpp module.h noble-bls12-381.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a combined.js ids.js generate_ids noble-bls12-381.bytecode noble-bls12-381.bytecode.h
