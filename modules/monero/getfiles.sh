#!/bin/bash
rm -f int-util.h; wget https://raw.githubusercontent.com/monero-project/monero/master/contrib/epee/include/int-util.h
rm -f groestl.c; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/groestl.c
rm -f groestl.h; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/groestl.h
rm -f groestl_tables.h; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/groestl_tables.h
rm -f jh.c; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/jh.c
rm -f jh.h; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/jh.h
rm -f skein.c; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/skein.c
rm -f skein.h; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/skein.h
rm -f skein_port.h; wget https://raw.githubusercontent.com/monero-project/monero/master/src/crypto/skein_port.h
