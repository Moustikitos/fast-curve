#include "ecdsa.h"


Sig *ecdsa_sign(Sig *sig, mpz_t msg, mpz_t secret0, mpz_t k, short canonical) {
    Point Q;
    mpz_t ns2, invk;
    mpz_inits(invk, ns2, sig->r, NULL);

    point_mul(&Q, &G, k);
    mpz_invert(invk, k, n);
    mpz_mod(sig->r, Q.x, n);

    if (mpz_cmp_ui(sig->r, 0) != 0){
        mpz_init(sig->s);
        mpz_mul(sig->s, secret0, sig->r);
        mpz_add(sig->s, sig->s, msg);
        mpz_mul(sig->s, sig->s, invk);
        mpz_mod(sig->s, sig->s, n);
        mpz_div_ui(ns2, n, 2);
        if (mpz_cmp_ui(sig->s, 0) == 0){
            mpz_init_set_ui(sig->r, 0);
        } else if (canonical > 0 && mpz_cmp(sig->s, ns2) > 0){
            mpz_sub(sig->s, n, sig->s);
        }
    } else {
        mpz_init_set_ui(sig->s, 0);
    }

    mpz_clears(invk, ns2, NULL);
}


HexSig *sign(char *digest, char *secret, char *nonce, short canonical) {
    static HexSig hS;
    Sig sig;
    mpz_t msg, secret0, k;

    mpz_init_set_str(msg, digest, 16);
    mpz_init_set_str(secret0, secret, 16);
    mpz_init_set_str(k, nonce, 16);
    mpz_mod(k, k, n);
    ecdsa_sign(&sig, msg, secret0, k, canonical);
    mpz_get_str(hS.r, 16, sig.r);
    mpz_get_str(hS.s, 16, sig.s);

    mpz_clears(msg, secret0, k, sig.r, sig.s, NULL);
    return &hS;
}


short verify(char *msg, char *x, char *y, char *hr, char*hs) {
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


EXPORT void main(){
    Sig sig;

    mpz_t msg, secret0, k;
    mpz_init_set_str(msg, "3819ff1b5125e14102ae429929e815d6fada758d4a6886a03b1b1c64aca3a53a", 16);
    mpz_init_set_str(secret0, "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b", 16);
    mpz_init_set_str(k, "63b10ab7890453eb4110b20cb3ed61004e684028c5d05cc4d046569e9cb4cdae", 16);

    for (int i=0; i<1000; i++){
        ecdsa_sign(&sig, msg, secret0, k, 1);
    }

    gmp_printf("r = %Zx\ns = %Zx\n", sig.r, sig.s);
}
