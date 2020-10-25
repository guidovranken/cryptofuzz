all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
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
		$(CRYPTO_JS_PATH)/src/ripemd160.js \
		$(CRYPTO_JS_PATH)/src/hmac.js \
		$(CRYPTO_JS_PATH)/src/pbkdf2.js \
		$(CRYPTO_JS_PATH)/src/cipher-core.js \
		$(CRYPTO_JS_PATH)/src/aes.js \
		$(CRYPTO_JS_PATH)/src/mode-ecb.js \
		$(CRYPTO_JS_PATH)/src/mode-cfb.js \
		$(CRYPTO_JS_PATH)/src/mode-ctr.js \
		$(CRYPTO_JS_PATH)/src/mode-ofb.js \
		$(CRYPTO_JS_PATH)/src/pad-nopadding.js \
		$(CRYPTO_JS_PATH)/src/pad-iso10126.js \
		$(CRYPTO_JS_PATH)/src/rc4.js \
		$(CRYPTO_JS_PATH)/src/rabbit.js \
		ids.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js crypto-js.bytecode
crypto-js.bytecode.h : crypto-js.bytecode
	xxd -i crypto-js.bytecode >crypto-js.bytecode.h
module.o: module.cpp module.h crypto-js.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
	rm -rf *.o module.a generate_ids ids.js combined.js crypto-js.bytecode crypto-js.bytecode.h
