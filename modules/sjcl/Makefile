all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBFUZZER_JS_PATH)/quickjs/libquickjs.a
	ar rcs module.a module.o $(LIBFUZZER_JS_PATH)/js.o tmp/*
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
sjcl.bytecode : header.js harness.js ids.js
	test $(LIBFUZZER_JS_PATH)
	test $(SJCL_PATH)
	rm -rf sjcl.bytecode
	cat \
		header.js \
		$(SJCL_PATH)/sjcl.js \
		ids.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js sjcl.bytecode
sjcl.bytecode.h : sjcl.bytecode
	xxd -i sjcl.bytecode >sjcl.bytecode.h
module.o: module.cpp module.h sjcl.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
