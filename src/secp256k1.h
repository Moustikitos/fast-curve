#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>


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

#ifndef SECP256K1_CONSTANTS
#define SECP256K1_CONSTANTS
static mpz_t p, n;
static Point G;
#endif


void set_infinity(Point *P) {
    mpz_init_set_ui(P->x, 0);
    mpz_init_set_ui(P->y, 0);
}


short is_infinity(const Point *P) {
    return mpz_cmp_ui(P->x, 0) == 0 && mpz_cmp_ui(P->y, 0) == 0 ? 1 : 0;
}


short has_square_y(const Point *P) {
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
    mpz_clears(y_sq, y_2, pp1s4, NULL);
}


Point *point_copy(const Point *P){
    static Point copy;
    mpz_init_set(copy.x, P->x);
    mpz_init_set(copy.y, P->y);
    return &copy;
}


void point_add(Point *sum, Point *P1, Point *P2) {
    if (is_infinity(P1)) {
        if (is_infinity(P2)) {
            return set_infinity(sum);
        } else {
            mpz_init_set(sum->x, P2->x);
            mpz_init_set(sum->y, P2->y);
            return;   
        }
    } else if (is_infinity(P2)) {
        mpz_init_set(sum->x, P1->x);
        mpz_init_set(sum->y, P1->y);
        return;
    } else {
        // check if points sum is infinity element
        mpz_t negy;
        mpz_init(negy);
        mpz_sub(negy, p, P2->y);
        if (mpz_cmp(P1->x, P2->x) == 0 && mpz_cmp(P1->y, negy) == 0) {
            mpz_clear(negy);
            return set_infinity(sum);
        }
    }

    mpz_t pm2, lambda;
    mpz_inits(pm2, lambda, NULL);
    mpz_sub_ui(pm2, p, 2);
    // if (xP1 == xP2):
    if (mpz_cmp(P1->x, P2->x) == 0) {
        // if yP1 != yP2: --> point P2 not on curve
        if (mpz_cmp(P1->y, P2->y) != 0) {
            mpz_clears(pm2, lambda, NULL);
            return set_infinity(sum);
        } else {
            mpz_t xp1_2, _2yp1;
            mpz_inits(xp1_2, _2yp1, NULL);
            // lam = (3 * xP1 * xP1 * pow(2 * yP1, p - 2, p)) % p
            mpz_mul(xp1_2, P1->x, P1->x);   // xp1_2 <- P1.x * P1.x 
            mpz_mul_ui(xp1_2, xp1_2, 3);    // xp1_2 <- 3 * xp1_2
            mpz_mul_ui(_2yp1, P1->y, 2);    // _2yp1 <- 2 * P1.y
            mpz_powm(_2yp1, _2yp1, pm2, p); // _2yp1 <- pow(_2yp1, pm2, p)
            mpz_mul(lambda, xp1_2, _2yp1);
            mpz_clears(xp1_2, _2yp1, NULL);
        }
    } else {
        mpz_t diff_x, diff_y;
        mpz_inits(diff_x, diff_y, NULL);
        // lam = ((yP2 - yP1) * pow(xP2 - xP1, p - 2, p)) % p
        mpz_sub(diff_y, P2->y, P1->y);
        mpz_sub(diff_x, P2->x, P1->x);
        mpz_powm(diff_x, diff_x, pm2, p);
        mpz_mul(lambda, diff_y, diff_x);
        mpz_clears(diff_x, diff_y, NULL);
    }
    mpz_mod(lambda, lambda, p);
    // x3 = (lam * lam - xP1 - xP2) % p
    mpz_inits(sum->x, sum->y, NULL);
    mpz_mul(sum->x, lambda, lambda);
    mpz_sub(sum->x, sum->x, P1->x);
    mpz_sub(sum->x, sum->x, P2->x);
    mpz_mod(sum->x, sum->x, p);
    // return [x3, (lam * (xP1 - x3) - yP1) % p]
    mpz_sub(sum->y, P1->x, sum->x);
    mpz_mul(sum->y, sum->y, lambda);
    mpz_sub(sum->y, sum->y, P1->y);
    mpz_mod(sum->y, sum->y, p);

    mpz_clears(pm2, lambda, NULL);
}


void point_mul(Point *prod, const Point *P, const mpz_t scalar) {
    Point R, *tmp;
    mpz_init_set(R.x, P->x);
    mpz_init_set(R.y, P->y);
    mpz_init_set_ui(prod->x, 0);
    mpz_init_set_ui(prod->y, 0);
    // for i in number of bits:
    int dbits = mpz_sizeinbase(scalar, 2);
    for (int i = 0; i < dbits; i++) {
        // if ((n >> i) & 1):
        if (mpz_tstbit(scalar, i)) {
            // R = point_add(R, P)
            point_add(prod, &R, point_copy(prod));
        }
        // P = point_add(P, P)
        tmp = point_copy(&R);
        point_add(&R, tmp, tmp);
    }
    mpz_clears(R.x, R.y, tmp->x, tmp->y, NULL);
}


EXPORT HexPoint *point_hexlify(Point *P) {
    static HexPoint hP;
    mpz_get_str(hP.x, 16, P->x);
    mpz_get_str(hP.y, 16, P->y);
    return &hP;
}


// for direct python use within python
EXPORT HexPoint *py_point_add(char *x1, char*y1, char *x2, char *y2) {
    Point P1, P2, Sum;
    mpz_init_set_str(P1.x, x1, 16);
    mpz_init_set_str(P1.y, y1, 16);
    mpz_init_set_str(P2.x, x2, 16);
    mpz_init_set_str(P2.y, y2, 16);
    point_add(&Sum, &P1, &P2);
    return point_hexlify(&Sum);
}


// for direct python use within python
EXPORT HexPoint *py_point_mul(char *x, char*y, char *k) {
    Point P, Mul;
    mpz_t n;
    mpz_init_set_str(P.x, x, 16);
    mpz_init_set_str(P.y, y, 16);
    mpz_init_set_str(n, k, 16);
    point_mul(&Mul, &P, n);
    return point_hexlify(&Mul);
}


// build point from hexadecimal string absissa value
EXPORT HexPoint *hex_point_from_hex_x(char *hex) {
    static Point P;
    mpz_init_set_str(P.x, hex, 16);
    mpz_init(P.y);
    y_from_x(P.y, P.x);
    return point_hexlify(&P);
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


EXPORT char *encoded_from_puk(Point *P) {
    static char enc[67];
    char xP[67];
    mpz_get_str(xP, 16, P->x); 
    enc[0] = '0';
    enc[1] = mpz_tstbit(P->y, 0) == 0 ? '2' : '3';
    for (int i=2; i < 66; i++){enc[i] = xP[i-2];}
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


EXPORT void init() {
    mpz_init_set_str(p, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    mpz_init_set_str(n, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    mpz_init_set_str(G.x, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    mpz_init_set_str(G.y, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
}
