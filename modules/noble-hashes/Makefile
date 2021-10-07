all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
noble-hashes.bytecode : header.js harness.js ids.js
	test $(LIBFUZZER_JS_PATH)
	test $(NOBLE_HASHES_PATH)
	rm -rf noble-hashes.bytecode
	cat header.js $(NOBLE_HASHES_PATH) ids.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js noble-hashes.bytecode
noble-hashes.bytecode.h : noble-hashes.bytecode
	xxd -i noble-hashes.bytecode >noble-hashes.bytecode.h
module.o: module.cpp module.h noble-hashes.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a combined.js ids.js generate_ids noble-hashes.bytecode noble-hashes.bytecode.h
