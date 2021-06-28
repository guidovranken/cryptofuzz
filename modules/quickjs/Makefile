all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_calc_ops : generate_calc_ops.cpp
	$(CXX) $(CXXFLAGS) generate_calc_ops.cpp -o generate_calc_ops
calc_ops.js : generate_calc_ops
	./generate_calc_ops >calc_ops.js
quickjs.bytecode : harness.js calc_ops.js
	test $(LIBFUZZER_JS_PATH)
	rm -rf quickjs.bytecode
	cat calc_ops.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js quickjs.bytecode
quickjs.bytecode.h : quickjs.bytecode
	xxd -i quickjs.bytecode >quickjs.bytecode.h
module.o: module.cpp module.h quickjs.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a calc_ops.js combined.js generate_calc_ops quickjs.bytecode quickjs.bytecode.h
