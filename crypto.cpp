#include <cryptofuzz/crypto.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

namespace cryptofuzz {
namespace crypto {
namespace impl {

/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

#define ROR(x,n) __builtin_rotateright32(x,n)
#define ROL(x,n) __builtin_rotateleft32(x,n)
#define ROLc(x,n) ROL(x,n)
#define RORc(x,n) ROR(x,n)

#define XMEMCPY memcpy

#define LTC_ARGCHK(...)

#define MIN(x, y) ( ((x)<(y))?(x):(y) )

#define STORE32H(x, y)                          \
do { ulong32 ttt = __builtin_bswap32 ((x));     \
      XMEMCPY ((y), &ttt, 4); } while(0)

#define LOAD32H(x, y)                           \
do { XMEMCPY (&(x), (y), 4);                    \
      (x) = __builtin_bswap32 ((x)); } while(0)

#define STORE64H(x, y)                          \
do { ulong64 ttt = __builtin_bswap64 ((x));     \
      XMEMCPY ((y), &ttt, 8); } while(0)

#define LOAD64H(x, y)                           \
do { XMEMCPY (&(x), (y), 8);                    \
      (x) = __builtin_bswap64 ((x)); } while(0)

typedef uint64_t ulong64;
typedef uint32_t ulong32;

/* error codes [will be expanded in future releases] */
enum {
   CRYPT_OK=0,             /* Result OK */
   CRYPT_ERROR,            /* Generic Error */
   CRYPT_NOP,              /* Not a failure but no operation was performed */

   CRYPT_INVALID_KEYSIZE,  /* Invalid key size given */
   CRYPT_INVALID_ROUNDS,   /* Invalid number of rounds */
   CRYPT_FAIL_TESTVECTOR,  /* Algorithm failed test vectors */

   CRYPT_BUFFER_OVERFLOW,  /* Not enough space for output */
   CRYPT_INVALID_PACKET,   /* Invalid input packet given */

   CRYPT_INVALID_PRNGSIZE, /* Invalid number of bits for a PRNG */
   CRYPT_ERROR_READPRNG,   /* Could not read enough from PRNG */

   CRYPT_INVALID_CIPHER,   /* Invalid cipher specified */
   CRYPT_INVALID_HASH,     /* Invalid hash specified */
   CRYPT_INVALID_PRNG,     /* Invalid PRNG specified */

   CRYPT_MEM,              /* Out of memory */

   CRYPT_PK_TYPE_MISMATCH, /* Not equivalent types of PK keys */
   CRYPT_PK_NOT_PRIVATE,   /* Requires a private PK key */

   CRYPT_INVALID_ARG,      /* Generic invalid argument */
   CRYPT_FILE_NOTFOUND,    /* File Not Found */

   CRYPT_PK_INVALID_TYPE,  /* Invalid type of PK key */

   CRYPT_OVERFLOW,         /* An overflow of a value was detected/prevented */

   CRYPT_PK_ASN1_ERROR,    /* An error occurred while en- or decoding ASN.1 data */

   CRYPT_INPUT_TOO_LONG,   /* The input was longer than expected. */

   CRYPT_PK_INVALID_SIZE,  /* Invalid size input for PK parameters */

   CRYPT_INVALID_PRIME_SIZE,/* Invalid size of prime requested */
   CRYPT_PK_INVALID_PADDING, /* Invalid padding on input */

   CRYPT_HASH_OVERFLOW      /* Hash applied to too many bits */
};

#define HASH_PROCESS(func_name, compress_name, state_var, block_size)                       \
int func_name (hash_state * md, const unsigned char *in, unsigned long inlen)               \
{                                                                                           \
    unsigned long n;                                                                        \
    int           err;                                                                      \
    LTC_ARGCHK(md != NULL);                                                                 \
    LTC_ARGCHK(in != NULL);                                                                 \
    if (md-> state_var .curlen > sizeof(md-> state_var .buf)) {                             \
       return CRYPT_INVALID_ARG;                                                            \
    }                                                                                       \
    if ((md-> state_var .length + inlen * 8) < md-> state_var .length) {                        \
      return CRYPT_HASH_OVERFLOW;                                                           \
    }                                                                                       \
    while (inlen > 0) {                                                                     \
        if (md-> state_var .curlen == 0 && inlen >= block_size) {                           \
           if ((err = compress_name (md, in)) != CRYPT_OK) {                                \
              return err;                                                                   \
           }                                                                                \
           md-> state_var .length += block_size * 8;                                        \
           in             += block_size;                                                    \
           inlen          -= block_size;                                                    \
        } else {                                                                            \
           n = MIN(inlen, (block_size - md-> state_var .curlen));                           \
           XMEMCPY(md-> state_var .buf + md-> state_var.curlen, in, (size_t)n);             \
           md-> state_var .curlen += n;                                                     \
           in             += n;                                                             \
           inlen          -= n;                                                             \
           if (md-> state_var .curlen == block_size) {                                      \
              if ((err = compress_name (md, md-> state_var .buf)) != CRYPT_OK) {            \
                 return err;                                                                \
              }                                                                             \
              md-> state_var .length += 8*block_size;                                       \
              md-> state_var .curlen = 0;                                                   \
           }                                                                                \
       }                                                                                    \
    }                                                                                       \
    return CRYPT_OK;                                                                        \
}

struct sha1_state {
    ulong64 length;
    ulong32 state[5], curlen;
    unsigned char buf[64];
};

typedef union Hash_state {
    char dummy[1];
    struct sha1_state   sha1;
    void *data;
} hash_state;

/**
  @file sha1.c
  LTC_SHA1 code by Tom St Denis
*/


#define F0(x,y,z)  (z ^ (x & (y ^ z)))
#define F1(x,y,z)  (x ^ y ^ z)
#define F2(x,y,z)  ((x & y) | (z & (x | y)))
#define F3(x,y,z)  (x ^ y ^ z)

#ifdef LTC_CLEAN_STACK
static int ss_sha1_compress(hash_state *md, const unsigned char *buf)
#else
static int  s_sha1_compress(hash_state *md, const unsigned char *buf)
#endif
{
    ulong32 a,b,c,d,e,W[80],i;
#ifdef LTC_SMALL_CODE
    ulong32 t;
#endif

    /* copy the state into 512-bits into W[0..15] */
    for (i = 0; i < 16; i++) {
        LOAD32H(W[i], buf + (4*i));
    }

    /* copy state */
    a = md->sha1.state[0];
    b = md->sha1.state[1];
    c = md->sha1.state[2];
    d = md->sha1.state[3];
    e = md->sha1.state[4];

    /* expand it */
    for (i = 16; i < 80; i++) {
        W[i] = ROL(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);
    }

    /* compress */
    /* round one */
    #define FF0(a,b,c,d,e,i) e = (ROLc(a, 5) + F0(b,c,d) + e + W[i] + 0x5a827999UL); b = ROLc(b, 30);
    #define FF1(a,b,c,d,e,i) e = (ROLc(a, 5) + F1(b,c,d) + e + W[i] + 0x6ed9eba1UL); b = ROLc(b, 30);
    #define FF2(a,b,c,d,e,i) e = (ROLc(a, 5) + F2(b,c,d) + e + W[i] + 0x8f1bbcdcUL); b = ROLc(b, 30);
    #define FF3(a,b,c,d,e,i) e = (ROLc(a, 5) + F3(b,c,d) + e + W[i] + 0xca62c1d6UL); b = ROLc(b, 30);

#ifdef LTC_SMALL_CODE

    for (i = 0; i < 20; ) {
       FF0(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 40; ) {
       FF1(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 60; ) {
       FF2(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

    for (; i < 80; ) {
       FF3(a,b,c,d,e,i++); t = e; e = d; d = c; c = b; b = a; a = t;
    }

#else

    for (i = 0; i < 20; ) {
       FF0(a,b,c,d,e,i++);
       FF0(e,a,b,c,d,i++);
       FF0(d,e,a,b,c,i++);
       FF0(c,d,e,a,b,i++);
       FF0(b,c,d,e,a,i++);
    }

    /* round two */
    for (; i < 40; )  {
       FF1(a,b,c,d,e,i++);
       FF1(e,a,b,c,d,i++);
       FF1(d,e,a,b,c,i++);
       FF1(c,d,e,a,b,i++);
       FF1(b,c,d,e,a,i++);
    }

    /* round three */
    for (; i < 60; )  {
       FF2(a,b,c,d,e,i++);
       FF2(e,a,b,c,d,i++);
       FF2(d,e,a,b,c,i++);
       FF2(c,d,e,a,b,i++);
       FF2(b,c,d,e,a,i++);
    }

    /* round four */
    for (; i < 80; )  {
       FF3(a,b,c,d,e,i++);
       FF3(e,a,b,c,d,i++);
       FF3(d,e,a,b,c,i++);
       FF3(c,d,e,a,b,i++);
       FF3(b,c,d,e,a,i++);
    }
#endif

    #undef FF0
    #undef FF1
    #undef FF2
    #undef FF3

    /* store */
    md->sha1.state[0] = md->sha1.state[0] + a;
    md->sha1.state[1] = md->sha1.state[1] + b;
    md->sha1.state[2] = md->sha1.state[2] + c;
    md->sha1.state[3] = md->sha1.state[3] + d;
    md->sha1.state[4] = md->sha1.state[4] + e;

    return CRYPT_OK;
}

#ifdef LTC_CLEAN_STACK
static int s_sha1_compress(hash_state *md, const unsigned char *buf)
{
   int err;
   err = ss_sha1_compress(md, buf);
   burn_stack(sizeof(ulong32) * 87);
   return err;
}
#endif

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha1_init(hash_state * md)
{
   LTC_ARGCHK(md != NULL);
   md->sha1.state[0] = 0x67452301UL;
   md->sha1.state[1] = 0xefcdab89UL;
   md->sha1.state[2] = 0x98badcfeUL;
   md->sha1.state[3] = 0x10325476UL;
   md->sha1.state[4] = 0xc3d2e1f0UL;
   md->sha1.curlen = 0;
   md->sha1.length = 0;
   return CRYPT_OK;
}

/**
   Process a block of memory though the hash
   @param md     The hash state
   @param in     The data to hash
   @param inlen  The length of the data (octets)
   @return CRYPT_OK if successful
*/
HASH_PROCESS(sha1_process, s_sha1_compress, sha1, 64)

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (20 bytes)
   @return CRYPT_OK if successful
*/
int sha1_done(hash_state * md, unsigned char *out)
{
    int i;

    LTC_ARGCHK(md  != NULL);
    LTC_ARGCHK(out != NULL);

    if (md->sha1.curlen >= sizeof(md->sha1.buf)) {
       return CRYPT_INVALID_ARG;
    }

    /* increase the length of the message */
    md->sha1.length += md->sha1.curlen * 8;

    /* append the '1' bit */
    md->sha1.buf[md->sha1.curlen++] = (unsigned char)0x80;

    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->sha1.curlen > 56) {
        while (md->sha1.curlen < 64) {
            md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
        }
        s_sha1_compress(md, md->sha1.buf);
        md->sha1.curlen = 0;
    }

    /* pad upto 56 bytes of zeroes */
    while (md->sha1.curlen < 56) {
        md->sha1.buf[md->sha1.curlen++] = (unsigned char)0;
    }

    /* store length */
    STORE64H(md->sha1.length, md->sha1.buf+56);
    s_sha1_compress(md, md->sha1.buf);

    /* copy output */
    for (i = 0; i < 5; i++) {
        STORE32H(md->sha1.state[i], out+(4*i));
    }
#ifdef LTC_CLEAN_STACK
    zeromem(md, sizeof(hash_state));
#endif
    return CRYPT_OK;
}
} /* namespace impl */

std::vector<uint8_t> sha1(const uint8_t* data, const size_t size) {
    uint8_t out[20];

    impl::hash_state md;
    impl::sha1_init(&md);
    impl::sha1_process(&md, data, size);
    impl::sha1_done(&md, out);

    return std::vector<uint8_t>(out, out + sizeof(out));
}

std::vector<uint8_t> sha1(const std::vector<uint8_t> data) {
    return sha1(data.data(), data.size());
}

} /* namespace crypto */
} /* namespace cryptofuzz */
