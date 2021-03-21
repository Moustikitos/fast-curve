#include "secp256k1.h"

// https://github.com/sipa/bips/blob/bip-taproot/bip-0340/reference.py


EXPORT char *tagged_hash(unsigned char *hash, char *tag, char *msg) {
    int return_ptr = 0;
    if (hash == NULL){
        static unsigned char _hash[33];
        hash = _hash;
        return_ptr = 1;
    }

    int len_msg = strlen(msg);
    char cat[65 + len_msg];
    char *tag_hash = hash_sha256(NULL, unhexlify(tag, strlen(tag)));

    int i;
    for (i=0; i < 32; i++){cat[i] = tag_hash[i];}
    for (i=32; i < 64; i++){cat[i] = tag_hash[i-32];}
    for (i=64; i < 64+len_msg; i++){cat[i] = msg[i-64];}
    cat[i] = '\0';
    if (return_ptr == 1) {
        return hash_sha256(NULL, unhexlify(cat, i));
    } else {
        hash_sha256(hash, unhexlify(cat, i));
        return NULL;
    }
}


EXPORT HexSig *sign(char *digest, char *secret, char *rand) {
    static HexSig hS;
    size_t i, len_digest;
    
    mpz_t d0, msg;
    len_digest = strlen(digest);
    mpz_init_set_str(msg, digest, 16);
    mpz_init_set_str(d0, secret, 16);
    mpz_mod(d0, d0, n);
    
    Point P;
    mpz_t k, t;
    char xP[65], hex_t[65], to_tag_hash[129 + len_digest];
    point_mul(&P, &G, d0);
    if (mpz_jacobi(P.y, p) != 1){mpz_sub(d0, n, d0);}
    mpz_get_str(xP, 16, P.x);
    mpz_init_set_str(t, tagged_hash(NULL, "BIP0340/aux", rand), 16);
    mpz_xor(t, d0, t);
    mpz_get_str(hex_t, 16, t);
    for (i=0; i < 64; i++){to_tag_hash[i] = hex_t[i];}
    for (i=64; i < 128; i++){to_tag_hash[i] = xP[i-64];}
    for (i=128; i < 128+len_digest; i++){to_tag_hash[i] = digest[i-128];}
    to_tag_hash[i] = '\0';
    mpz_init_set_str(k, tagged_hash(NULL, "BIP0340/nonce", to_tag_hash), 16);
    mpz_mod(k, k, n);

    if (mpz_cmp_ui(k, 0) == 0){return &hS;}

    Point R;
    mpz_t e;
    point_mul(&R, &G, k);
    if (mpz_jacobi(R.y, p) != 1){mpz_sub(k, n, k);}
    mpz_get_str(hS.r, 16, R.x);
    mpz_get_str(xP, 16, P.x);
    for (i=0; i < 64; i++){to_tag_hash[i] = hS.r[i];}
    mpz_init_set_str(e, tagged_hash(NULL, "BIP0340/challenge", to_tag_hash), 16);
    mpz_mod(e, e, n);

    mpz_mul(e, e, d0);
    mpz_add(e, k, e);
    mpz_mod(e, e, n);
    mpz_get_str(hS.s, 16, e);

    mpz_clears(k, t, e, d0, msg, R.x, R.y, P.x, P.y, NULL);
    return &hS;
}


EXPORT short verify(char *msg, char *x, char *hr, char*hs) {
    Point P;
    mpz_init_set_str(P.x, x, 16);
    mpz_init(P.y);
    y_from_x(P.y, P.x);
    if (mpz_cmp(P.x, p) >= 0 || mpz_cmp_ui(P.y, 0) == 0){
        mpz_clears(P.x, P.y, NULL);
        return 0;
    } else if (mpz_tstbit(P.y, 0) == 0){
        mpz_sub(P.y, p, P.y);
    }

    mpz_t r, s;
    mpz_init_set_str(r, hr, 16);
    mpz_init_set_str(s, hs, 16);
    if (mpz_cmp(r, n) >= 0 || mpz_cmp(s, n) >= 0){
        mpz_clears(r, s, P.x, P.y, NULL);
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
    mpz_init_set_str(e, tagged_hash(NULL, "BIP0340/challenge", to_tag_hash), 16);
    mpz_mod(e, e, n);

    Point R, Gs;
    mpz_sub(e, n, e);
    point_mul(&Gs, &G, s);
    point_mul(&R, &P, e);
    point_add(&R, &Gs, &R);

    if (is_infinity(&R) || mpz_jacobi(R.y, p) != 1 || mpz_cmp(R.x, r) != 0){
        mpz_clears(r, s, e, P.x, P.y, R.x, R.y, Gs.x, Gs.y, NULL);
        return 0;
    }
    mpz_clears(r, s, e, P.x, P.y, R.x, R.y, Gs.x, Gs.y, NULL);
    return 1;
}


EXPORT HexSig *bcrypto410_sign(char *digest, char *secret) {
    static HexSig hS;
    size_t i, len_digest;
    mpz_t d0, msg;

    len_digest = strlen(digest);
    mpz_init_set_str(msg, digest, 16);
    mpz_init_set_str(d0, secret, 16);
    
    mpz_t k; 
    char to_hash[131 + len_digest];
    for (i=0; i < 64; i++){to_hash[i] = secret[i];}
    for (i=64; i < 64+len_digest; i++){to_hash[i] = digest[i-64];}
    to_hash[i] = '\0';
    mpz_init_set_str(k, hash_sha256(NULL, unhexlify(to_hash, i)), 16);
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
    mpz_t e;
    char xP[65]; 
    point_mul(&P, &G, d0);
    mpz_get_str(xP, 16, P.x);
    for (i=0; i < 64; i++){to_hash[i] = hS.r[i];}
    to_hash[i] = '0';
    to_hash[i+1] = mpz_tstbit(P.y, 0) == 0 ? '2' : '3';
    for (i=66; i < 130; i++){to_hash[i] = xP[i-66];}
    for (i=130; i < 130+len_digest; i++){to_hash[i] = digest[i-130];}
    to_hash[i] = '\0';
    mpz_init_set_str(e, hash_sha256(NULL, unhexlify(to_hash, i)), 16);
    mpz_mod(e, e, n);

    mpz_mul(e, e, d0);
    mpz_add(e, k, e);
    mpz_mod(e, e, n);
    mpz_get_str(hS.s, 16, e);

    mpz_clears(k, e, d0, msg, P.x, P.y, R.x, R.y, NULL);
    return &hS;
}


EXPORT short bcrypto410_verify(char *msg, char *x, char *y, char *hr, char*hs) {
    mpz_t r, s, _y;
    mpz_init_set_str(_y, y, 16);
    mpz_init_set_str(r, hr, 16);
    mpz_init_set_str(s, hs, 16);
    if (mpz_cmp(r, p) >= 0 || mpz_cmp(s, n) >= 0){
        mpz_clears(r, s, _y, NULL);
        return 0;
    }

    mpz_t e;
    int i;
    int len_msg = strlen(msg);
    char to_hash[131 + len_msg];
    for (i=0; i < 64; i++){to_hash[i] = hr[i];}
    to_hash[64] = '0';
    to_hash[64+1] = mpz_tstbit(_y, 0) == 0 ? '2' : '3';
    for (i=66; i < 130; i++){to_hash[i] = x[i-66];}
    for (i=130; i < 130+len_msg; i++){to_hash[i] = msg[i-130];}
    to_hash[i] = '\0';
    mpz_init_set_str(e, hash_sha256(NULL, unhexlify(to_hash, i)), 16);
    mpz_mod(e, e, n);

    Point P;
    mpz_init_set_str(P.x, x, 16);
    mpz_init_set_str(P.y, y, 16);
    mpz_sub(e, n, e);
    point_mul(&P, &P, e);

    Point R;
    point_mul(&R, &G, s);
    point_add(&R, &R, &P);

    if (is_infinity(&R) == 1 || mpz_cmp(R.x, r) != 0 || mpz_jacobi(R.y, p) != 1){
        mpz_clears(r, s, _y, e, P.x, P.y, R.x, R.y, NULL);
        return 0;
    }
    mpz_clears(r, s, _y, e, P.x, P.y, R.x, R.y, NULL);
    return 1;
}
