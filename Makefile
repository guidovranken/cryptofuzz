all : cryptofuzz generate_dict generate_corpus

CXXFLAGS += -Wall -Wextra -std=c++17 -I include/ -I . -I fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL
REPOSITORY_HEADERS = repository_tbl.h repository_map.h
OBJECT_FILES = \
bignum_fuzzer_importer.o botan_importer.o builtin_tests_importer.o components.o crypto.o datasource.o driver.o \
ecc_diff_fuzzer_exporter.o ecc_diff_fuzzer_importer.o entry.o executor.o expmod.o mutator.o mutatorpool.o numbers.o \
openssl_importer.o operation.o options.o repository.o tests.o util.o wycheproof.o z3.o

$(REPOSITORY_HEADERS) &: gen_repository.py
	./gen_repository.py

%.o : %.cpp $(REPOSITORY_HEADERS)
	$(CXX) $(CXXFLAGS) $< -c -o $@
executor.o : executor.cpp config.h
	$(CXX) $(CXXFLAGS) executor.cpp -c -o executor.o
entry.o : entry.cpp extra_options.h repository_tbl.h
	$(CXX) $(CXXFLAGS) entry.cpp -c -o entry.o
components.o : components.cpp config.h
	$(CXX) $(CXXFLAGS) components.cpp -c -o components.o
mutator.o : mutator.cpp config.h expmod.h
	$(CXX) $(CXXFLAGS) mutator.cpp -c -o mutator.o
z3.o : z3.cpp config.h _z3.h
	$(CXX) $(CXXFLAGS) z3.cpp -c -o z3.o
numbers.o : numbers.cpp
	$(CXX) $(CXXFLAGS) -O0 numbers.cpp -c -o numbers.o

third_party/cpu_features/build/libcpu_features.a :
	cd third_party/cpu_features && rm -rf build && mkdir build && cd build && cmake .. && make

cryptofuzz : $(OBJECT_FILES) third_party/cpu_features/build/libcpu_features.a
	test $(LIBFUZZER_LINK)
	$(CXX) $(CXXFLAGS) $(OBJECT_FILES) $(shell find modules -type f -name module.a) $(LIBFUZZER_LINK) third_party/cpu_features/build/libcpu_features.a $(LINK_FLAGS) -o cryptofuzz

generate_dict: generate_dict.cpp repository_map.h
	$(CXX) $(CXXFLAGS) generate_dict.cpp -o generate_dict

generate_corpus: generate_corpus.cpp
	$(CXX) $(CXXFLAGS) generate_corpus.cpp -o generate_corpus

clean:
	rm -rf $(OBJECT_FILES) $(REPOSITORY_HEADERS) cryptofuzz generate_dict generate_corpus
