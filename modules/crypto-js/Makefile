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
crypto-js.bytecode : header.js harness.js ids.js
	test $(LIBFUZZER_JS_PATH)
	test $(CRYPTO_JS_PATH)
	rm -rf crypto-js.bytecode
	cat \
		header.js \
		$(CRYPTO_JS_PATH)/src/core.js \
		$(CRYPTO_JS_PATH)/src/x64-core.js \
		$(CRYPTO_JS_PATH)/src/md5.js \
		$(CRYPTO_JS_PATH)/src/sha1.js \
		$(CRYPTO_JS_PATH)/src/sha256.js \
		$(CRYPTO_JS_PATH)/src/sha512.js \
		$(CRYPTO_JS_PATH)/src/sha224.js \
		$(CRYPTO_JS_PATH)/src/sha384.js \
		$(CRYPTO_JS_PATH)/src/sha3.js \
		$(CRYPTO_JS_PATH)/src/hmac.js \
		$(CRYPTO_JS_PATH)/src/pbkdf2.js \
		ids.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js crypto-js.bytecode
crypto-js.bytecode.h : crypto-js.bytecode
	xxd -i crypto-js.bytecode >crypto-js.bytecode.h
module.o: module.cpp module.h crypto-js.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
