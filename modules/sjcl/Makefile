all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	ar rcs module.a module.o
	ranlib module.a
generate_ids : generate_ids.cpp
	$(CXX) $(CXXFLAGS) generate_ids.cpp -o generate_ids
ids.js : generate_ids
	./generate_ids >ids.js
sjcl.bytecode : header.js harness.js ids.js
	test $(LIBFUZZER_JS_PATH)
	test $(SJCL_PATH)
	rm -rf sjcl.bytecode
	cat \
		header.js \
		$(SJCL_PATH)/core/sjcl.js \
		$(SJCL_PATH)/core/aes.js \
		$(SJCL_PATH)/core/bitArray.js \
		$(SJCL_PATH)/core/bn.js \
		$(SJCL_PATH)/core/cbc.js \
		$(SJCL_PATH)/core/ccmArrayBuffer.js \
		$(SJCL_PATH)/core/ccm.js \
		$(SJCL_PATH)/core/codecArrayBuffer.js \
		$(SJCL_PATH)/core/codecBase32.js \
		$(SJCL_PATH)/core/codecBase64.js \
		$(SJCL_PATH)/core/codecBytes.js \
		$(SJCL_PATH)/core/codecHex.js \
		$(SJCL_PATH)/core/codecString.js \
		$(SJCL_PATH)/core/codecZ85.js \
		$(SJCL_PATH)/core/convenience.js \
		$(SJCL_PATH)/core/ctr.js \
		$(SJCL_PATH)/core/ecc.js \
		$(SJCL_PATH)/core/exports.js \
		$(SJCL_PATH)/core/gcm.js \
		$(SJCL_PATH)/core/hkdf.js \
		$(SJCL_PATH)/core/hmac.js \
		$(SJCL_PATH)/core/ocb2.js \
		$(SJCL_PATH)/core/ocb2progressive.js \
		$(SJCL_PATH)/core/pbkdf2.js \
		$(SJCL_PATH)/core/ripemd160.js \
		$(SJCL_PATH)/core/scrypt.js \
		$(SJCL_PATH)/core/sha1.js \
		$(SJCL_PATH)/core/sha256.js \
		$(SJCL_PATH)/core/sha512.js \
		$(SJCL_PATH)/core/srp.js \
		$(SJCL_PATH)/core/random.js \
		ids.js harness.js >combined.js
	$(LIBFUZZER_JS_PATH)/to_bytecode combined.js sjcl.bytecode
sjcl.bytecode.h : sjcl.bytecode
	xxd -i sjcl.bytecode >sjcl.bytecode.h
module.o: module.cpp module.h sjcl.bytecode.h
	test $(LIBFUZZER_JS_PATH)
	$(CXX) $(CXXFLAGS) -I $(LIBFUZZER_JS_PATH) -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a ids.js combined.js generate_ids sjcl.bytecode sjcl.bytecode.h
