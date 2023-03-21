all: module.a

CXXFLAGS += -Wall -Wextra -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
CryptofuzzBouncyCastleHarness.class : CryptofuzzBouncyCastleHarness.java
	test $(JDK_PATH)
	$(JDK_PATH)/bin/javac -cp $(BOUNCYCASTLE_JAR) CryptofuzzBouncyCastleHarness.java
module.o: module.cpp module.h CryptofuzzBouncyCastleHarness.class
	test $(JDK_PATH)
	$(CXX) \
	$(CXXFLAGS) \
	-I $(JDK_PATH)/include/ \
	-I $(JDK_PATH)/include/linux/ \
	-DCLASS_PATH="\"$(realpath .):$(BOUNCYCASTLE_JAR)\"" \
	-c module.cpp \
	-o module.o
clean:
	rm -rf *.o module.a CryptofuzzBouncyCastleHarness.class
