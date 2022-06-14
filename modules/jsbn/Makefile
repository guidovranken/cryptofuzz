all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_calc_ops : generate_calc_ops.cpp
	$(CXX) $(CXXFLAGS) generate_calc_ops.cpp -o generate_calc_ops
calc_ops.js : generate_calc_ops
	./generate_calc_ops >calc_ops.js
jsbn.bytecode : header.js harness.js calc_ops.js
	test $(LIBFUZZER_JS_PATH)
	test $(JSBN_PATH)
	rm -rf jsbn.bytecode
	cat header.js $(JSBN_PATH) calc_ops.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js jsbn.bytecode
jsbn.bytecode.h : jsbn.bytecode
	xxd -i jsbn.bytecode >jsbn.bytecode.h
module.o: module.cpp module.h jsbn.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a calc_ops.js combined.js generate_calc_ops jsbn.bytecode jsbn.bytecode.h
