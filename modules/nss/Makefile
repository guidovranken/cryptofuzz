all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(NSS_NSPR_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libnss_static.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libcertdb.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libpk11wrap_static.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libsoftokn_static.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libcerthi.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libcryptohi.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libnsspki.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libnssb.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libnssdev.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libnssutil.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libplds4.a && \
	ar x $(NSS_NSPR_PATH)/nspr/Debug/pr/src/libnspr4.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libplc4.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libnss_static.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libfreebl_static.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libhw-acc-crypto.a && \
	ar x $(NSS_NSPR_PATH)/nss/out/Debug/libgcm-aes-x86_c_lib.a


	ar rcs module.a module.o tmp/*.o
	rm -rf tmp/
	ranlib module.a
module.o: module.cpp module.h
	test $(NSS_NSPR_PATH)
	$(CXX) $(CXXFLAGS) -I $(NSS_NSPR_PATH)/dist/public/nss -I $(NSS_NSPR_PATH)/dist/Debug/include/nspr -I $(NSS_NSPR_PATH)/nss/lib/pk11wrap -fPIC -c module.cpp -o module.o
clean:
	rm -rf *.o module.a
