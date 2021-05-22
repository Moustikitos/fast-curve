#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <gmp.h>
#include "sha256.h"


// #define A2V(c) ((c) <= '9') ? (c) - '0' : ((c) <= 'f') ? (c) - 'a' + 10 : ((c) <= 'F') ? (c) - 'A' + 10 : 0


#if __linux__ 
    #define EXPORT extern
#elif _WIN32
    #define _USE_MATH_DEFINES // for C
    #define EXPORT __declspec(dllexport)
#endif


typedef struct {
    mpz_t x, y;
} Point;

typedef struct {
    char x[65], y[65];
} HexPoint;

typedef struct {
    mpz_t r, s;
} Sig;

typedef struct {
    char r[65], s[65];
} HexSig;


// secp256k1 constant as mp values
#ifndef SECP256K1_CONSTANTS
#define SECP256K1_CONSTANTS
static mpz_t p, n;
static Point G;
static const char P[65] = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
static const char N[65] = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
static const char XG[65] = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
static const char YG[65] = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
#endif

void y_from_x(mpz_t y, mpz_t x);

short point_on_curve(Point *P);
short is_infinity(Point *P);
short is_quad(mpz_t x);
short has_square_y(Point *P);

HexPoint *point_add(Point *sum, Point *P1, Point *P2);
HexPoint *point_mul(Point *prod, Point *P, mpz_t n);
HexPoint *point_hexlify(Point *);


EXPORT void init() {
    mpz_init_set_str(p, P, 16);
    mpz_init_set_str(n, N, 16);
    mpz_init_set_str(G.x, XG, 16);
    mpz_init_set_str(G.y, YG, 16);
}


short is_infinity(Point *P) {
    return mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0 ? 1 : 0;
}


short has_square_y(Point *P) {
    return is_infinity(P) == 0 && mpz_jacobi(P->y, p) == 1 ? 1 : 0;
}


short point_on_curve(Point *P) {
    mpz_t tmp, x3;
    mpz_init_set(tmp, P->y);
    mpz_init_set(x3, P->x);

    mpz_mul(tmp, tmp, P->y);
    mpz_mul(x3, x3, P->x);
    mpz_mul(x3, x3, P->x);
    mpz_sub(tmp, tmp, x3);
    mpz_sub_ui(tmp, tmp, 7);

    short test = mpz_cmp_ui(tmp, 0) == 0 ? 1 : 0;
    mpz_clears(tmp, x3, NULL);
    return test;
}


void destroy_point(Point *point) {
    mpz_clears(point->x, point->y, NULL);
    free(point);
}


void destroy_sig(Sig *sig) {
    mpz_clears(sig->r, sig->s, NULL);
    free(sig);
}


// Compute `y` from `x` according to `y²=x³+7`
void y_from_x(mpz_t y, mpz_t x) {
    mpz_t y_sq, y_2, pp1s4;
    // unsigned long int pp1s4;
    mpz_inits(y_sq, y_2, pp1s4, NULL);
    // y_sq = (pow(x, 3, p) + 7) % p
    mpz_powm_ui(y_sq, x, 3, p);
    mpz_add_ui(y_sq, y_sq, 7);
    mpz_mod(y_sq, y_sq, p);
    // y = pow(y_sq, (p + 1) // 4, p)
    mpz_add_ui(pp1s4, p, 1);
    mpz_fdiv_q_ui(pp1s4, pp1s4, 4);
    mpz_powm(y, y_sq, pp1s4, p);
    // if pow(y, 2, p) != y_sq:
    //     return None
    mpz_powm_ui(y_2, y, 2, p);
    if (mpz_cmp(y_2, y_sq) != 0) {
        mpz_init_set_ui(y, 0);
    }
    // return y
    mpz_clears(y_sq, y_2, pp1s4, NULL);
}


HexPoint *point_hexlify(Point *P) {
    static HexPoint hP;
    mpz_get_str(hP.x, 16, P->x);
    mpz_get_str(hP.y, 16, P->y);
    return &hP;
}


HexPoint *point_add(Point *sum, Point *P1, Point *P2) {
    int return_ptr = 0;
    if (sum == NULL){
        static Point _sum;
        sum = &_sum;
        return_ptr = 1;
    }

    int p1_is_inf = is_infinity(P1);
    int p2_is_inf = is_infinity(P2);
    if (p1_is_inf && p2_is_inf){
        mpz_init_set_ui(sum->x, 0);
        mpz_init_set_ui(sum->y,0);
        return (return_ptr == 1 ? point_hexlify(sum) : NULL);
    } else if (p1_is_inf) {
        mpz_init_set(sum->x, P2->x);
        mpz_init_set(sum->y, P2->y);
        return (return_ptr == 1 ? point_hexlify(sum) : NULL);
    } else if (p2_is_inf) {
        mpz_init_set(sum->x, P1->x);
        mpz_init_set(sum->y, P1->y);
        return (return_ptr == 1 ? point_hexlify(sum) : NULL);
    } else {
        // check if points sum is infinity element
        mpz_t negy;
        mpz_init(negy);
        mpz_sub(negy, p, P2->y);
        if (mpz_cmp(P1->x, P2->x) == 0 && mpz_cmp(P1->y, negy) == 0) {
            mpz_clear(negy);
            mpz_init_set_ui(sum->x, 0);
            mpz_init_set_ui(sum->y,0);
            return (return_ptr == 1 ? point_hexlify(sum) : NULL);
        }
    }

    mpz_t x, y, xp1_2, pm2, _2yp1, diff_x, diff_y, lambda;
    mpz_inits(x, y, xp1_2, pm2, _2yp1, diff_x, diff_y, lambda, NULL);
    mpz_sub_ui(pm2, p, 2);
    // if (xP1 == xP2):
    if (mpz_cmp(P1->x, P2->x) == 0) {
        // if yP1 != yP2:
        if (mpz_cmp(P1->y, P2->y) != 0) {
            mpz_clears(x, y, xp1_2, pm2, _2yp1, diff_x, diff_y, lambda, NULL);
            return (return_ptr == 1 ? point_hexlify(sum) : NULL);
        } else {
            // lam = (3 * xP1 * xP1 * pow(2 * yP1, p - 2, p)) % p
            mpz_mul(xp1_2, P1->x, P1->x);   // xp1_2 <- P1.x * P1.x 
            mpz_mul_ui(xp1_2, xp1_2, 3);    // xp1_2 <- 3 * xp1_2
            mpz_mul_ui(_2yp1, P1->y, 2);    // _2yp1 <- 2 * P1.y
            mpz_powm(_2yp1, _2yp1, pm2, p); // _2yp1 <- pow(_2yp1, pm2, p)
            mpz_mul(lambda, xp1_2, _2yp1);
        }
    } else {
        // lam = ((yP2 - yP1) * pow(xP2 - xP1, p - 2, p)) % p
        mpz_sub(diff_y, P2->y, P1->y);
        mpz_sub(diff_x, P2->x, P1->x);
        mpz_powm(diff_x, diff_x, pm2, p);
        mpz_mul(lambda, diff_y, diff_x);
    }
    mpz_mod(lambda, lambda, p);

    // x3 = (lam * lam - xP1 - xP2) % p
    mpz_mul(x, lambda, lambda);
    mpz_sub(x, x, P1->x);
    mpz_sub(x, x, P2->x);
    mpz_mod(x, x, p);

    // return [x3, (lam * (xP1 - x3) - yP1) % p]
    mpz_sub(y, P1->x, x);
    mpz_mul(y, y, lambda);
    mpz_sub(y, y, P1->y);
    mpz_mod(y, y, p);

    mpz_init_set(sum->x, x);
    mpz_init_set(sum->y, y);
    mpz_clears(x, y, xp1_2, pm2, _2yp1, diff_x, diff_y, lambda, NULL);

    return (return_ptr == 1 ? point_hexlify(sum) : NULL);
}


EXPORT HexPoint *py_point_add(char *x1, char*y1, char *x2, char *y2) {
    Point P1, P2;
    mpz_init_set_str(P1.x, x1, 16);
    mpz_init_set_str(P1.y, y1, 16);
    mpz_init_set_str(P2.x, x2, 16);
    mpz_init_set_str(P2.y, y2, 16);
    return point_add(NULL, &P1, &P2);
}


HexPoint *point_mul(Point *prod, Point *P, mpz_t n) {
    int return_ptr = 0;
    if (prod == NULL){
        static Point _prod;
        prod = &_prod;
        return_ptr = 1;
    }

    Point tmp;
    mpz_init_set(tmp.x, P->x);
    mpz_init_set(tmp.y, P->y);
    mpz_init_set_ui(prod->x, 0);
    mpz_init_set_ui(prod->y, 0);

    // for i in range(256):
    int dbits = mpz_sizeinbase(n, 2);
    for (int i = 0; i < dbits; i++) {
        // if ((n >> i) & 1):
        if (mpz_tstbit(n, i)) {
            // R = point_add(R, P)
            point_add(prod, prod, &tmp);
        }
        // P = point_add(P, P)
        point_add(&tmp, &tmp, &tmp);
    }
    // return R
    return (return_ptr == 1 ? point_hexlify(prod) : NULL);
}


EXPORT HexPoint *py_point_mul(char *x, char*y, char *k) {
    Point P;
    mpz_t n;
    mpz_init_set_str(P.x, x, 16);
    mpz_init_set_str(P.y, y, 16);
    mpz_init_set_str(n, k, 16);
    return point_mul(NULL, &P, n);
}


EXPORT char *hexlify(unsigned char *buffer, const int len_buffer) {
    static char *hex;
    char v2a[] = "0123456789abcdef";
    char *phex, tmp;
    int len = (len_buffer << 1);

    hex = (char *)malloc((len + 1)*sizeof(char));
    phex = hex;
    for(int i=0; i<len_buffer; i++) {
        tmp = buffer[i];
        *phex++ = v2a[(tmp >> 4) & 0x0F];
        *phex++ = v2a[tmp & 0x0F];
    }
    *phex++ = '\0';
    return hex;
}


int A2V(char c) {
    if ((c >= '0') && (c <= '9')){
        return c - '0';
    }
    if ((c >= 'a') && (c <= 'f')){
        return c - 'a' + 10;
    }
    else return 0;
}


EXPORT unsigned char *unhexlify(char *buffer, const int len_buffer) {
    static unsigned char *bstr;
    int len = (len_buffer>>1);

    bstr = (unsigned char *)malloc((len+1)*sizeof(unsigned char));
    for (int i = 0; i < len; i++) {
        bstr[i] = (A2V(buffer[i<<1]) << 4) + A2V(buffer[(i<<1)+1]);
    }
    bstr[len] = '\0';
    return bstr;
}


EXPORT char *hash_sha256(unsigned char *hash, unsigned char *msg) {
    int return_ptr = 0;
    if (hash == NULL){
        static unsigned char _hash[32];
        hash = _hash;
        return_ptr = 1;
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, strlen((unsigned char *)msg));
    sha256_final(&ctx, hash);

    return (return_ptr == 1 ? hexlify(hash, 32) : NULL);
}


EXPORT char *hash_sha256_s(unsigned char *hash, unsigned char *msg, int len_msg) {
    int return_ptr = 0;
    if (hash == NULL){
        static unsigned char _hash[32];
        hash = _hash;
        return_ptr = 1;
    }

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, msg, len_msg);
    sha256_final(&ctx, hash);

    return (return_ptr == 1 ? hexlify(hash, 32) : NULL);
}


// build point from hexadecimal string absisse value
EXPORT HexPoint *hex_point_from_hex_x(char *hex) {
    static HexPoint hP;
    mpz_t x, y;

    mpz_init_set_str(x, hex, 16);
    mpz_init(y);
    y_from_x(y, x);

    mpz_get_str(hP.x, 16, x);
    mpz_get_str(hP.y, 16, y);
    return &hP;
}


char *encoded_from_puk(Point *P) {
    static char enc[67];
    char xP[67];

    mpz_get_str(xP, 16, P->x); 
    enc[0] = '0';
    enc[1] = mpz_tstbit(P->y, 0) == 0 ? '2' : '3';
    for (int i=2; i < 66; i++){enc[i] = xP[i-2];}
    return enc;
}


EXPORT char *encoded_from_hex_puk(char *x, char *y) {
    static char enc[67];
    mpz_t _y;
    mpz_init_set_str(_y, y, 16);
    enc[0] = '0';
    enc[1] = mpz_tstbit(_y, 0) == 0 ? '2' : '3';
    for (int i=2; i < 66; i++){enc[i] = x[i-2];}
    return enc;
}


EXPORT HexPoint *hex_puk_from_encoded(char enc[67]) {
    static HexPoint hP;
    char x[65], y[3];
    int test, i;
    Point tmp;

    y[2] = '\0';
    for (i=0; i<2; i++){
        y[i] = enc[i];
    }
    x[64] = '\0';
    for (i=2; i<66; i++){
        x[i-2] = enc[i];
    }

    mpz_init_set_str(tmp.x, &x[0], 16);
    mpz_init(tmp.y);
    y_from_x(tmp.y, tmp.x);

    test = (int) mpz_fdiv_ui(tmp.y, 2);
    if (test != atoi(y) - 2){
        mpz_neg(tmp.y, tmp.y);
        mpz_mod(tmp.y, tmp.y, p);
    }

    mpz_get_str(hP.x, 16, tmp.x);
    mpz_get_str(hP.y, 16, tmp.y);
    return &hP;
}


EXPORT HexPoint *hex_puk_from_hex(char *hex) {
    static HexPoint hP;
    mpz_t k;
    Point tmp;

    mpz_init_set_str(k, hex, 16);
    point_mul(&tmp, &G, k);

    mpz_get_str(hP.x, 16, tmp.x);
    mpz_get_str(hP.y, 16, tmp.y);
    return &hP;
}
