#include "secp256k1.h"


EXPORT HexSig *sign(char *digest, char *secret, char *nonce, short canonical) {
    static HexSig hS;
    mpz_t invk, ns2, msg, secret0, k, r, s;
    Point Q;

    mpz_inits(invk, ns2, r, s, NULL);
    mpz_init_set_str(msg, digest, 16);
    mpz_init_set_str(secret0, secret, 16);
    mpz_init_set_str(k, nonce, 16);
    mpz_mod(k, k, n);
    point_mul(&Q, &G, k);
    mpz_invert(invk, k, n);
    mpz_mod(r, Q.x, n);

    if (mpz_cmp_ui(r, 0) == 0){
        mpz_init_set_ui(s, 0);
    } else {
        mpz_mul(s, secret0, r);
        mpz_add(s, s, msg);
        mpz_mul(s, s, invk);
        mpz_mod(s, s, n);
        mpz_div_ui(ns2, n, 2);
        if (mpz_cmp_ui(s, 0) == 0){
            mpz_init_set_ui(r, 0);
        } else if (canonical > 0 && mpz_cmp(s, ns2) > 0){
            mpz_sub(s, n, s);
        }
    }

    mpz_get_str(hS.r, 16, r);
    mpz_get_str(hS.s, 16, s);

    mpz_clears(invk, ns2, msg, secret0, k, r, s, NULL);
    return &hS;
}


EXPORT short verify(char *msg, char *x, char *y, char *hr, char*hs) {
    Point pubkey;
    mpz_t h, s, r;

    mpz_init_set_str(pubkey.x, x, 16);
    mpz_init_set_str(pubkey.y, y, 16);
    mpz_init_set_str(r, hr, 16);
    mpz_init_set_str(s, hs, 16);
    mpz_init_set_str(h, msg, 16);
    if (mpz_cmp_ui(r, 0) == 0 || mpz_cmp(r, n) > 0 || mpz_cmp(s, n) > 0){
        return 0;
    }

    Point u1G, u2Q, GQ;
    mpz_t c, hc, rc, nm2;
    short result;
    mpz_inits(c, hc, rc, nm2, GQ.x, GQ.y, NULL);
    mpz_invert(c, s, n);
    mpz_mul(hc, h, c);
    mpz_mod(hc, hc, n);
    point_mul(&u1G, &G, hc);
    mpz_mul(rc, r, c);
    mpz_mod(rc, rc, n);
    point_mul(&u2Q, &pubkey, rc);
    point_add(&GQ, &u1G, &u2Q);
    mpz_mod(GQ.x, GQ.x, n);
    result = mpz_cmp(GQ.x, r) == 0 ? 1 : 0;

    mpz_clears(h, s, r, c, hc, rc, nm2, NULL);
    return result;
}
