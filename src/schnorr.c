#include "schnorr.h"

/*
schnorr signatures from
https://github.com/sipa/bips/blob/bip-taproot/bip-0340/reference.py
*/

char *tagged_hash(char *tag, char *msg, int len_msg) {
    unsigned char hash[33];
    char cat[129 + len_msg];
    char *tag_hash = hash_sha256_s(tag, strlen(tag));

    int i;
    for (i=0; i < 64; i++){cat[i] = tag_hash[i];}
    for (i=64; i < 128; i++){cat[i] = tag_hash[i-64];}
    for (i=128; i < 128+len_msg; i++){cat[i] = msg[i-128];}
    cat[i] = '\0';
    return hash_sha256_s(unhexlify(cat, i), i>>1);
}


char *_mpz_get_str_16(mpz_t value){
    static char str_16[65];
    mpz_get_str(str_16, 16, value);

    size_t len_str_16 = strlen(str_16);
    size_t delta = 64 - len_str_16;
    if (delta > 0){
        for (size_t i=63; i >= delta; i--){str_16[i] = str_16[i-delta];}
        for (size_t i=0; i < delta; i++){str_16[i] = '0';}
    }
    str_16[64] = '\0';
    return str_16;
}


HexSig *sign(char *digest, char *secret, char *rand) {
    static HexSig hS;
    size_t i, len_digest;
    
    mpz_t d0;
    len_digest = strlen(digest);
    mpz_init_set_str(d0, secret, 16);
    
    Point P;
    mpz_t k, t;
    char xP[65], hex_t[65], to_tag_hash[129 + len_digest];
    point_mul(&P, &G, d0);
    if (mpz_fdiv_ui(P.y, 2) != 0){mpz_sub(d0, n, d0);}
    mpz_get_str(xP, 16, P.x);
    mpz_init_set_str(t, tagged_hash("BIP0340/aux", rand, 64), 16);
    mpz_xor(t, d0, t);
    mpz_get_str(hex_t, 16, t);

    // test vector #3 fix
    // check if len hex_t == 64 and left fill with '0' if not
    size_t len_t = strlen(hex_t);
    size_t delta = 64 - len_t;
    if (delta > 0){
        for (i=0; i < delta; i++){to_tag_hash[i] = '0';}
    }
    // and continue concatenation
    for (i=delta; i < 64; i++){to_tag_hash[i] = hex_t[i-delta];}
    for (i=64; i < 128; i++){to_tag_hash[i] = xP[i-64];}
    for (i=128; i < 128+len_digest; i++){to_tag_hash[i] = digest[i-128];}
    to_tag_hash[i] = '\0';
    
    mpz_init_set_str(k, tagged_hash("BIP0340/nonce", to_tag_hash, 128+len_digest), 16);
    mpz_mod(k, k, n);

    if (mpz_cmp_ui(k, 0) == 0){return &hS;}

    Point R;
    mpz_t e;
    point_mul(&R, &G, k);
    if (mpz_fdiv_ui(R.y, 2) != 0){mpz_sub(k, n, k);}
    mpz_get_str(hS.r, 16, R.x);
    mpz_get_str(xP, 16, P.x);
    for (i=0; i < 64; i++){to_tag_hash[i] = hS.r[i];}
    mpz_init_set_str(e, tagged_hash("BIP0340/challenge", to_tag_hash, 128+len_digest), 16);
    mpz_mod(e, e, n);

    mpz_mul(e, e, d0);
    mpz_add(e, k, e);
    mpz_mod(e, e, n);
    mpz_get_str(hS.s, 16, e);

    mpz_clears(k, t, e, d0, R.x, R.y, P.x, P.y, NULL);
    return &hS;
}


short verify(char *msg, char *x, char *hr, char*hs) {
    Point P;
    mpz_t big1;
    mpz_init_set_str(P.x, x, 16);
    mpz_init_set_ui(big1, 1);
    mpz_init(P.y);
    y_from_x(P.y, P.x);
    // if y & 1 != 0:
    //     y = p-y
    mpz_and(big1, P.y, big1);
    if (mpz_cmp_ui(big1, 0) != 0){mpz_sub(P.y, p, P.y);}
    if (mpz_cmp(P.x, p) >= 0 || mpz_cmp_ui(P.y, 0) == 0){
        mpz_clears(P.x, P.y, big1, NULL);
        return 0;
    }

    mpz_t r, s;
    mpz_init_set_str(r, hr, 16);
    mpz_init_set_str(s, hs, 16);
    if (mpz_cmp(r, n) >= 0 || mpz_cmp(s, n) >= 0){
        mpz_clears(r, s, P.x, P.y, big1, NULL);
        return 0;
    }

    mpz_t e;
    int i;
    int len_msg = strlen(msg);
    char to_tag_hash[129+len_msg];
    for (i=0; i < 64; i++){to_tag_hash[i] = hr[i];}
    for (i=64; i < 128; i++){to_tag_hash[i] = x[i-64];}
    for (i=128; i < 128+len_msg; i++){to_tag_hash[i] = msg[i-128];}
    to_tag_hash[i] = '\0';
    mpz_init_set_str(e, tagged_hash("BIP0340/challenge", to_tag_hash, 128+len_msg), 16);
    mpz_mod(e, e, n);

    Point R, Gs;
    mpz_sub(e, n, e);
    point_mul(&Gs, &G, s);
    point_mul(&R, &P, e);
    point_add(&R, &Gs, point_copy(&R));
    
    if (mpz_cmp(R.x, r) == 0){
        mpz_clears(r, s, e, P.x, P.y, R.x, R.y, Gs.x, Gs.y, big1, NULL);
        return 1;
    }
    mpz_clears(r, s, e, P.x, P.y, R.x, R.y, Gs.x, Gs.y, big1, NULL);
    return 0;
}

/*
schnorr signatures from
https://github.com/bcoin-org/bcrypto/blob/v4.1.0/lib/js/schnorr.js
*/

HexSig *bcrypto410_sign(char *digest, char *secret) {
    static HexSig hS;
    size_t i, len_digest;
    mpz_t d0, msg;

    len_digest = strlen(digest);
    mpz_init_set_str(msg, digest, 16);
    mpz_init_set_str(d0, secret, 16);
    
    char to_hash[131 + len_digest];
    for (i=0; i < 64; i++){to_hash[i] = secret[i];}
    for (i=64; i < 64+len_digest; i++){to_hash[i] = digest[i-64];}
    to_hash[i] = '\0';
    mpz_t k; 
    mpz_init_set_str(k, hash_sha256(unhexlify(to_hash, i)), 16);
    mpz_mod(k, k, n);
    if (mpz_cmp_ui(k, 0) == 0){
        mpz_clears(k, d0, msg, NULL);
        return &hS;
    }

    Point R;
    point_mul(&R, &G, k);
    mpz_get_str(hS.r, 16, R.x);
    if (mpz_jacobi(R.y, p) != 1){mpz_sub(k, n, k);}

    Point P;
    char *xP;
    point_mul(&P, &G, d0);
    xP = _mpz_get_str_16(P.x);
    // check if len r == 64 and left fill with '0' if not
    size_t len_r = strlen(hS.r);
    size_t delta = 64 - len_r;
    if (delta > 0){
        for (i=0; i < delta; i++){to_hash[i] = '0';}
    }
    // and continue concatenation
    for (i=delta; i < 64; i++){to_hash[i] = hS.r[i-delta];}
    to_hash[i] = '0';
    to_hash[i+1] = mpz_odd_p(P.y) == 0 ? '2' : '3';
    for (i=66; i < 130; i++){to_hash[i] = xP[i-66];}
    for (i=130; i < 130+len_digest; i++){to_hash[i] = digest[i-130];}
    to_hash[i] = '\0';
    mpz_t e;
    mpz_init_set_str(e, hash_sha256(unhexlify(to_hash, i)), 16);
    mpz_mod(e, e, n);

    mpz_mul(e, e, d0);
    mpz_add(e, k, e);
    mpz_mod(e, e, n);
    mpz_get_str(hS.s, 16, e);

    mpz_clears(k, e, d0, msg, P.x, P.y, R.x, R.y, NULL);
    return &hS;
}


short bcrypto410_verify(char *msg, char *x, char *y, char *hr, char*hs) {
    mpz_t r, s, _y;
    mpz_init_set_str(_y, y, 16);
    mpz_init_set_str(r, hr, 16);
    mpz_init_set_str(s, hs, 16);
    if (mpz_cmp(r, p) >= 0 || mpz_cmp(s, n) >= 0){
        mpz_clears(r, s, _y, NULL);
        return 0;
    }

    mpz_t e;
    size_t i;
    size_t len_msg = strlen(msg);
    char to_hash[131 + len_msg];
    // check if len hr == 64 and left fill with '0' if not
    size_t len_hr = strlen(hr);
    size_t delta = 64 - len_hr;
    if (delta > 0){
        for (i=0; i < delta; i++){to_hash[i] = '0';}
    }
    // and continue concatenation
    for (i=delta; i < 64; i++){to_hash[i] = hr[i-delta];}
    to_hash[64] = '0';
    to_hash[64+1] = mpz_odd_p(_y) == 0 ? '2' : '3';
    for (i=66; i < 130; i++){to_hash[i] = x[i-66];}
    for (i=130; i < 130+len_msg; i++){to_hash[i] = msg[i-130];}
    to_hash[i] = '\0';
    mpz_init_set_str(e, hash_sha256(unhexlify(to_hash, i)), 16);
    mpz_mod(e, e, n);

    Point P;
    mpz_init_set_str(P.x, x, 16);
    mpz_init_set_str(P.y, y, 16);
    mpz_sub(e, n, e);
    point_mul(&P, &P, e);

    Point R;
    point_mul(&R, &G, s);
    point_add(&R, point_copy(&R), &P);

    if (mpz_cmp(R.x, r) == 0){
        mpz_clears(r, s, _y, e, P.x, P.y, R.x, R.y, NULL);
        return 1;
    }
    mpz_clears(r, s, _y, e, P.x, P.y, R.x, R.y, NULL);
    return 0;
}


EXPORT void main(){
    HexSig *sig;
    char msg[] = "3819ff1b5125e14102ae429929e815d6fada758d4a6886a03b1b1c64aca3a53a";
    char prk[] = "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b";
    char rnd[] = "32609657b627fbbda461f14887a62dc0d74b02af7585ed191576dbd3cd7677fd";

    for (int i=0; i<1000; i++){
        sig = sign(msg, prk, rnd);
    }

    gmp_printf("r = %s\ns = %s\n", sig->r, sig->s);
}
