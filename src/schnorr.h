#ifndef _SCHNORR_H
#define _SCHNORR_H

#include "secp256k1.h"
#include "sha256.h"

static char V2A[] = "0123456789abcdef";

int A2V(char c) {
    if ((c >= '0') && (c <= '9')){return c - '0';}
    if ((c >= 'a') && (c <= 'f')){return c - 'a' + 10;}
    else return 0;
}


char *hexlify(unsigned char *buffer, const int len_buffer) {
    static char *hex;
    char *phex;
    hex = (char *)malloc((len_buffer << 1) + 1);
    phex = hex;
    for(int i=0; i<len_buffer; i++) {
        *phex++ = V2A[(buffer[i] >> 4) & 0x0F];
        *phex++ = V2A[buffer[i] & 0x0F];
    }
    *phex++ = '\0';
    return hex;
}


unsigned char *unhexlify(char *buffer, const int len_buffer) {
    static unsigned char *bstr;
    int len = (len_buffer>>1);
    bstr = (unsigned char *)malloc(len + 1);
    for (int i = 0; i < len; i++) {
        bstr[i] = (A2V(buffer[i<<1]) << 4) + A2V(buffer[(i<<1)+1]);
    }
    bstr[len] = '\0';
    return bstr;
}


char *hash_sha256_s(unsigned char *msg, int len_msg) {
    unsigned char hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, len_msg);
    sha256_final(&ctx, hash);
    return hexlify(hash, 32);
}


EXPORT char *hash_sha256(unsigned char *msg) {
    return hash_sha256_s(msg, strlen(msg));
}

EXPORT short bcrypto410_verify(char *msg, char *x, char *y, char *hr, char*hs);
EXPORT HexSig *bcrypto410_sign(char *digest, char *secret);
EXPORT short verify(char *msg, char *x, char *hr, char*hs);
EXPORT HexSig *sign(char *digest, char *secret, char *rand);
EXPORT char *tagged_hash(char *tag, char *msg, int len_msg);

#endif
