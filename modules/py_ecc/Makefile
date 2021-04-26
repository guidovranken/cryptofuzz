all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
module.o: module.cpp module.h
	test $(CRYPTOFUZZ_CPYTHON_PATH)
	$(CXX) $(CXXFLAGS) -I $(CRYPTOFUZZ_CPYTHON_PATH)/include/python3.8/ -DCRYPTOFUZZ_CPYTHON_PATH="\"$(CRYPTOFUZZ_CPYTHON_PATH)\"" -DCRYPTOFUZZ_CPYTHON_VENV_PATH="\"$(CRYPTOFUZZ_CPYTHON_VENV_PATH)\"" -DPY_ECC_HARNESS_PATH="\"$(realpath harness.py)\"" -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a tmp/
