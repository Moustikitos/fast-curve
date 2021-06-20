#include "ecdsa.h"


Sig *ecdsa_sign(mpz_t msg, mpz_t secret0, mpz_t k, short canonical) {
    static Sig sig;
    Point Q;
    mpz_t ns2, invk;
    mpz_inits(invk, ns2, NULL);

    point_mul(&Q, &G, k);
    mpz_invert(invk, k, n);
    mpz_mod(sig.r, Q.x, n);

    if (mpz_cmp_ui(sig.r, 0) != 0){
        mpz_mul(sig.s, secret0, sig.r);
        mpz_add(sig.s, sig.s, msg);
        mpz_mul(sig.s, sig.s, invk);
        mpz_mod(sig.s, sig.s, n);
        mpz_div_ui(ns2, n, 2);
        if (mpz_cmp_ui(sig.s, 0) == 0){
            mpz_init_set_ui(sig.r, 0);
        } else if (canonical > 0 && mpz_cmp(sig.s, ns2) > 0){
            mpz_sub(sig.s, n, sig.s);
        }
    } else {
        mpz_init_set_ui(sig.s, 0);
    }

    mpz_clears(invk, ns2, NULL);
    return &sig;
}


short verify(mpz_t msg, Point *pubkey, Sig *sig) {
    if (mpz_cmp_ui(sig->r, 0) == 0 || mpz_cmp(sig->r, n) > 0 || mpz_cmp(sig->s, n) > 0){
        return 0;
    }

    Point u1G, u2Q, GQ;
    mpz_t c, hc, rc, nm2;
    short result;
    mpz_inits(c, hc, rc, nm2, GQ.x, GQ.y, NULL);
    mpz_invert(c, sig->s, n);
    mpz_mul(hc, msg, c);
    mpz_mod(hc, hc, n);
    point_mul(&u1G, &G, hc);
    mpz_mul(rc, sig->r, c);
    mpz_mod(rc, rc, n);
    point_mul(&u2Q, pubkey, rc);
    point_add(&GQ, &u1G, &u2Q);
    mpz_mod(GQ.x, GQ.x, n);
    result = mpz_cmp(GQ.x, sig->r) == 0 ? 1 : 0;

    mpz_clears(c, hc, rc, nm2, NULL);
    return result;
}


static PyObject *_curve_init(PyObject *self, PyObject *args) {
    init();
    Py_INCREF(Py_None);
    return Py_None;
}


static PyObject *_ecdsa_sign(PyObject *self, PyObject *args) {
    char *data, *secret, *rnd;
    short canonical;

    if (!PyArg_ParseTuple(args, "sssh", &data, &secret, &rnd, &canonical)) {
        return NULL;
    }

    mpz_t msg, secret0, k;
    mpz_init_set_str(msg, data, 16);
    mpz_init_set_str(secret0, secret, 16);
    mpz_init_set_str(k, rnd, 16);

    Sig *sig = ecdsa_sign(msg, secret0, k, canonical);
    PyObject *ret = Py_BuildValue("ss", mpz_get_str(NULL, 16, sig->r), mpz_get_str(NULL, 16, sig->s));

    mpz_clears(msg, secret0, k, NULL);
    return ret;
}


static PyObject *_ecdsa_verify(PyObject *self, PyObject *args) {
    // char * r, * s, * msg, * qx, * qy, * p, * a, * b, * q, * gx, * gy;

    // if (!PyArg_ParseTuple(args, "sssssssssss", &r, &s, &msg, &qx, &qy, &p, &a, &b, &q, &gx, &gy)) {
    //     return NULL;
    // }

    // Sig sig;
    // mpz_init_set_str(sig.r, r, 10);
    // mpz_init_set_str(sig.s, s, 10);

    // CurveZZ_p * curve = buildCurveZZ_p(p, a, b, q, gx, gy, 10);
    // int valid = 0;

    // PointZZ_p * Q = buildPointZZ_p(qx, qy, 10);
    // valid = verifyZZ_p(&sig, msg, Q, curve);

    // destroyCurveZZ_p(curve);
    // destroyPointZZ_p(Q);

    // mpz_clears(sig.r, sig.s, NULL);
    // return Py_BuildValue("O", valid ? Py_True : Py_False);
}


static PyMethodDef _ecdsa__methods__[] = {
    {"init", _curve_init, METH_VARARGS, "Initialize SECP256K1 curve"},
    {"sign", _ecdsa_sign, METH_VARARGS, "Sign a message via ECDSA."},
    {"verify", _ecdsa_verify, METH_VARARGS, "Verify a signature via ECDSA."},
    {NULL, NULL, 0, NULL}  /* Sentinel */
};


#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "_ecdsa",  /* m_name */
    NULL,      /* m_doc */
    -1,  /* m_size */
    _ecdsa__methods__,  /* m_methods */
    NULL,  /* m_reload */
    NULL,  /* m_traverse */
    NULL,  /* m_clear */
    NULL,  /* m_free */
};

PyMODINIT_FUNC PyInit__ecdsa(void) {
    PyObject * m = PyModule_Create(&moduledef);
    return m;
}

#else
PyMODINIT_FUNC init_ecdsa(void) {
    Py_InitModule("_ecdsa", _ecdsa__methods__);
}

#endif
