all: module.a

CXXFLAGS += -Wall -Wextra -Werror -std=c++17 -I ../../include -I ../../fuzzing-headers/include -DFUZZING_HEADERS_NO_IMPL

module.a: module.o
	test $(NSS_NSPR_PATH)
	rm -rf module.a
	rm -rf tmp/
	mkdir tmp/
	cd tmp && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnss_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libcertdb.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libpk11wrap_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libsoftokn_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libcerthi.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libcryptohi.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnsspki.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnssb.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnssdev.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnssutil.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libplds4.a && \
	ar x $(NSS_NSPR_PATH)/nspr/Debug/pr/src/libnspr4.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libplc4.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libnss_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libfreebl_static.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libhw-acc-crypto.a && \
	ar x $(NSS_NSPR_PATH)/dist/Debug/lib/libgcm-aes-x86_c_lib.a


	ar rcs module.a module.o tmp/*.o
	rm -rf tmp/
	ranlib module.a
module.o: module.cpp module.h
	test $(NSS_NSPR_PATH)
	$(CXX) $(CXXFLAGS) -I $(NSS_NSPR_PATH)/dist/public/nss -I $(NSS_NSPR_PATH)/dist/Debug/include/nspr -I $(NSS_NSPR_PATH)/nss/lib/pk11wrap -I $(NSS_NSPR_PATH)/nss/cpputil -fPIC -c module.cpp -o module.o

clean:
	rm -rf *.o module.a
