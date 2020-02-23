all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && ar x $(LIBFUZZER_JS_PATH)/quickjs/libquickjs.a
	ar rcs module.a module.o $(LIBFUZZER_JS_PATH)/js.o tmp/*
	ranlib module.a
generate_calc_ops : generate_calc_ops.cpp
	$(CXX) $(CXXFLAGS) generate_calc_ops.cpp -o generate_calc_ops
calc_ops.js : generate_calc_ops
	./generate_calc_ops >calc_ops.js
bignumber.js.bytecode : header.js harness.js calc_ops.js
	test $(LIBFUZZER_JS_PATH)
	test $(BIGNUMBER_JS_PATH)
	rm -rf bignumber.js.bytecode
	cat header.js $(BIGNUMBER_JS_PATH) calc_ops.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js bignumber.js.bytecode
bignumber.js.bytecode.h : bignumber.js.bytecode
	xxd -i bignumber.js.bytecode >bignumber.js.bytecode.h
module.o: module.cpp module.h bignumber.js.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
