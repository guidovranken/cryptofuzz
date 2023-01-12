all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o nimobjects/
	rm -rf module.a
	ar rcs module.a module.o nimobjects/*.o
	ranlib module.a
nimobjects/ : nim_bigints_harness.nim
	test $(NIM_PATH)
	rm -rf nimobjects/
	$(NIM_PATH)/bin/nimble -n --nim:$(NIM_PATH)/bin/nim install https://github.com/nim-lang/bigints
	$(NIM_PATH)/bin/nim c -d:release --noMain --noLinking --header:nim_bigints_harness.h nim_bigints_harness.nim
	mkdir nimobjects/
	cd nimobjects/ && $(CC) $(CFLAGS) -c -I$(HOME)/.cache/nim/nim_bigints_harness_r/ -I$(NIM_PATH)/lib/ $(HOME)/.cache/nim/nim_bigints_harness_r/*.c
module.o: nimobjects/ module.cpp module.h
	$(CXX) $(CXXFLAGS) -I$(HOME)/.cache/nim/nim_bigints_harness_r/ -I$(NIM_PATH)/lib/ -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a nimobjects/
