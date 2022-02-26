#!/bin/bash

set -eu

# Import Wycheproof test vectors
#
# Usage: ./import_wycheproof.sh <corpus directory>

if [ ! -x "./cryptofuzz" ]; then
    echo "Build Cryptofuzz first"
    exit 1
fi

if [ -d "wycheproof" ]; then
    echo "Remove directory wycheproof first"
    exit 1
fi

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    exit 1
fi

CORPUS_DIR="$1"

if [ ! -d "$CORPUS_DIR" ]; then
    echo "Directory does not exist"
    exit 1
fi


git clone --depth 1 https://github.com/google/wycheproof
find wycheproof/testvectors/ -type f -name 'ecdsa_*' -exec ./cryptofuzz --from-wycheproof={},$CORPUS_DIR \;
find wycheproof/testvectors/ -type f -name 'ecdh_*' -exec ./cryptofuzz --from-wycheproof={},$CORPUS_DIR \;

rm -rf wycheproof/
