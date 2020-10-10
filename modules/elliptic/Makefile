all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
elliptic.bytecode : header.js harness.js ids.js
	test $(LIBFUZZER_JS_PATH)
	test $(ELLIPTIC_JS_PATH)
	rm -rf elliptic.bytecode
	cat header.js $(ELLIPTIC_JS_PATH) ids.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js elliptic.bytecode
elliptic.bytecode.h : elliptic.bytecode
	xxd -i elliptic.bytecode >elliptic.bytecode.h
module.o: module.cpp module.h elliptic.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a ids.js combined.js generate_ids elliptic.bytecode elliptic.bytecode.h
