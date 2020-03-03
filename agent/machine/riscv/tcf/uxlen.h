typedef struct {
    uint64_t l;
    uint64_t h;
} int_xlen_t;

static unsigned xlen = 0;

static int_xlen_t fix_sign(int_xlen_t v, unsigned bits, int sign) {
    int_xlen_t mask;
    mask.h = 0;
    if (bits < 64) {
        mask.l = ((uint64_t)1 << bits) - 1;
    }
    else {
        mask.l = ~(uint64_t)0;
        if (bits > 64) {
            assert(bits == 128);
            mask.h = ~(uint64_t)0;
        }
    }
    if (sign) {
        if (bits <= 64) sign = (v.l & ((uint64_t)1 << (bits - 1))) != 0;
        else sign = (v.h & ((uint64_t)1 << (bits - 65))) != 0;
    }
    if (sign) {
        v.l |= ~mask.l;
        v.h |= ~mask.h;
    }
    else {
        v.l &= mask.l;
        v.h &= mask.h;
    }
    return v;
}

static int int_xlen_cmpu(int_xlen_t x, int_xlen_t y) {
    if (xlen > 64) {
        if (x.h < y.h) return -1;
        if (x.h > y.h) return +1;
    }
    if (x.l < y.l) return -1;
    if (x.l > y.l) return +1;
    return 0;
}

static int int_xlen_cmpi(int_xlen_t x, int_xlen_t y) {
    if (xlen > 64) {
        if ((int64_t)x.h < (int64_t)y.h) return -1;
        if ((int64_t)x.h > (int64_t)y.h) return +1;
    }
    if ((int64_t)x.l < (int64_t)y.l) return -1;
    if ((int64_t)x.l > (int64_t)y.l) return +1;
    return 0;
}

static int_xlen_t int_xlen_neg(int_xlen_t x) {
    int_xlen_t z;
    z.l = ~x.l + 1;
    z.h = ~x.h;
    if (z.l < ~x.l) z.h++;
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_add(int_xlen_t x, int_xlen_t y) {
    int_xlen_t z;
    z.l = x.l + y.l;
    z.h = x.h + y.h;
    if (z.l < x.l) z.h++;
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_sub(int_xlen_t x, int_xlen_t y) {
    int_xlen_t z;
    int_xlen_t n = int_xlen_neg(y);
    z.l = x.l + n.l;
    z.h = x.h + n.h;
    if (z.l < x.l) z.h++;
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_from_u(uint64_t x) {
    int_xlen_t z;
    z.l = x;
    z.h = 0;
    return z;
}

static int_xlen_t int_xlen_from_i(int64_t x) {
    int_xlen_t z;
    z.l = x;
    z.h = x < 0 ? (int64_t)-1 : 0;
    return z;
}

static int_xlen_t int_xlen_from_u2(uint64_t x, uint64_t y) {
    int_xlen_t z;
    z.l = x;
    z.h = y;
    return z;
}

#define int_xlen_to_l(x) ((x).l)
#define int_xlen_to_h(x) ((x).h)
#define int_xlen_add_u(x, y) int_xlen_add(x, int_xlen_from_u(y))
#define int_xlen_add_i(x, y) int_xlen_add(x, int_xlen_from_i(y))

static int_xlen_t int_xlen_sll(int_xlen_t x, unsigned y) {
    int_xlen_t z;
    unsigned i;
    z.l = z.h = 0;
    for (i = 0; i < xlen; i++) {
        int b = 0;
        if (i >= y) {
            unsigned j = i - y;
            if (j < 64) {
                b = (x.l & ((uint64_t)1 << j)) != 0;
            }
            else {
                b = (x.h & ((uint64_t)1 << (j - 64))) != 0;
            }
        }
        if (b) {
            if (i < 64) {
                z.l |= (uint64_t)1 << i;
            }
            else {
                z.h |= (uint64_t)1 << (i - 64);
            }
        }
    }
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_srl(int_xlen_t x, unsigned y) {
    int_xlen_t z;
    unsigned i;
    z.l = z.h = 0;
    for (i = 0; i < xlen; i++) {
        int b = 0;
        if (i + y < xlen) {
            unsigned j = i + y;
            if (j < 64) {
                b = (x.l & ((uint64_t)1 << j)) != 0;
            }
            else {
                b = (x.h & ((uint64_t)1 << (j - 64))) != 0;
            }
        }
        if (b) {
            if (i < 64) {
                z.l |= (uint64_t)1 << i;
            }
            else {
                z.h |= (uint64_t)1 << (i - 64);
            }
        }
    }
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_sra(int_xlen_t x, unsigned y) {
    int_xlen_t z;
    unsigned i;
    z.l = z.h = 0;
    for (i = 0; i < xlen; i++) {
        int b = 0;
        unsigned j = i + y;
        if (j >= xlen) j = xlen - 1;
        if (j < 64) {
            b = (x.l & ((uint64_t)1 << j)) != 0;
        }
        else {
            b = (x.h & ((uint64_t)1 << (j - 64))) != 0;
        }
        if (b) {
            if (i < 64) {
                z.l |= (uint64_t)1 << i;
            }
            else {
                z.h |= (uint64_t)1 << (i - 64);
            }
        }
    }
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_and(int_xlen_t x, int_xlen_t y) {
    int_xlen_t z;
    z.l = x.l & y.l;
    z.h = x.h & y.h;
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_xor(int_xlen_t x, int_xlen_t y) {
    int_xlen_t z;
    z.l = x.l ^ y.l;
    z.h = x.h ^ y.h;
    return fix_sign(z, xlen, 1);
}

static int_xlen_t int_xlen_or(int_xlen_t x, int_xlen_t y) {
    int_xlen_t z;
    z.l = x.l | y.l;
    z.h = x.h | y.h;
    return fix_sign(z, xlen, 1);
}
