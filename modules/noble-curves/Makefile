all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
noble-curves.bytecode : harness.js ids.js
	test $(LIBFUZZER_JS_PATH)
	rm -rf noble-curves.bytecode noble-curves.js
	npm i && npm run build
	$(LIBFUZZER_JS_PATH)/to_bytecode noble-curves.js noble-curves.bytecode
noble-curves.bytecode.h : noble-curves.bytecode
	xxd -i noble-curves.bytecode >noble-curves.bytecode.h
module.o: module.cpp module.h noble-curves.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a noble-curves.js ids.js generate_ids noble-curves.bytecode noble-curves.bytecode.h
