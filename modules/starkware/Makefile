all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o ff-cairo-harness.json common-ec-cairo-harness.json cairo-alt_bn128-harness.json
	ar rcs module.a module.o
	ranlib module.a
ff-cairo-harness.json : ff-cairo-harness.cairo
	cairo-compile ff-cairo-harness.cairo --cairo_path="ff-cairo/lib" --output ff-cairo-harness.json
common-ec-cairo-harness.json : common-ec-cairo-harness.cairo
	cairo-compile common-ec-cairo-harness.cairo --cairo_path="common-ec-cairo/ec" --output common-ec-cairo-harness.json
cairo-alt_bn128-harness.json : cairo-alt_bn128-harness.cairo
	cairo-compile cairo-alt_bn128-harness.cairo --cairo_path="cairo-alt_bn128/" --output cairo-alt_bn128-harness.json
module.o: module.cpp module.h
	test $(CRYPTOFUZZ_CPYTHON_PATH)
	$(CXX) $(CXXFLAGS) -I $(CRYPTOFUZZ_CPYTHON_PATH)/include/python3.8/ -DCRYPTOFUZZ_CPYTHON_PATH="\"$(CRYPTOFUZZ_CPYTHON_PATH)\"" -DCRYPTOFUZZ_CPYTHON_VENV_PATH="\"$(CRYPTOFUZZ_CPYTHON_VENV_PATH)\"" -DPY_ECC_HARNESS_PATH="\"$(realpath harness.py)\"" -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
