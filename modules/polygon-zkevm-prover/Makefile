all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o fq.o fq.asm.o fr.o fr.asm.o alt_bn128.o splitparstr.o naf.o
	ar rcs module.a module.o fq.o fq.asm.o fr.o fr.asm.o alt_bn128.o splitparstr.o naf.o
	ranlib module.a
fq.o : $(ZKEVM_PROVER_PATH)/src/ffiasm/fq.cpp
	$(CXX) $(CXXFLAGS) -g -c $(ZKEVM_PROVER_PATH)/src/ffiasm/fq.cpp
fq.asm.o : $(ZKEVM_PROVER_PATH)/src/ffiasm/fq.asm
	nasm -felf64 $(ZKEVM_PROVER_PATH)/src/ffiasm/fq.asm -o fq.asm.o
fr.o : $(ZKEVM_PROVER_PATH)/src/ffiasm/fr.cpp
	$(CXX) $(CXXFLAGS) -g -c $(ZKEVM_PROVER_PATH)/src/ffiasm/fr.cpp
fr.asm.o : $(ZKEVM_PROVER_PATH)/src/ffiasm/fr.asm
	nasm -felf64 $(ZKEVM_PROVER_PATH)/src/ffiasm/fr.asm -o fr.asm.o
alt_bn128.o : $(ZKEVM_PROVER_PATH)/src/ffiasm/alt_bn128.cpp
	$(CXX) $(CXXFLAGS) -g -c $(ZKEVM_PROVER_PATH)/src/ffiasm/alt_bn128.cpp
splitparstr.o : $(ZKEVM_PROVER_PATH)/src/ffiasm/splitparstr.cpp
	$(CXX) $(CXXFLAGS) -g -c $(ZKEVM_PROVER_PATH)/src/ffiasm/splitparstr.cpp
naf.o : $(ZKEVM_PROVER_PATH)/src/ffiasm/naf.cpp
	$(CXX) $(CXXFLAGS) -g -c $(ZKEVM_PROVER_PATH)/src/ffiasm/naf.cpp
module.o: module.cpp module.h
	test $(ZKEVM_PROVER_PATH)
	$(CXX) $(CXXFLAGS) -I $(ZKEVM_PROVER_PATH)/src/ffiasm -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
