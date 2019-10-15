static unsigned xlen = 0;

typedef struct {
    uint64_t l;
    uint64_t h;
} uxlen_t;

static int uxlen_cmp(uxlen_t x, uxlen_t y) {
    if (xlen > 64) {
        if (x.h < y.h) return -1;
        if (x.h > y.h) return +1;
    }
    if (x.l < y.l) return -1;
    if (x.l > y.l) return +1;
    return 0;
}

static uxlen_t uxlen_neg(uxlen_t x) {
    uxlen_t z;
    z.l = ~x.l + 1;
    z.h = ~x.h;
    if (z.l < ~x.l) z.h++;
    return z;
}

static uxlen_t uxlen_add(uxlen_t x, uxlen_t y) {
    uxlen_t z;
    z.l = x.l + y.l;
    z.h = x.h + y.h;
    if (z.l < x.l) z.h++;
    return z;
}

static uxlen_t uxlen_sub(uxlen_t x, uxlen_t y) {
    uxlen_t z;
    uxlen_t n = uxlen_neg(y);
    z.l = x.l + n.l;
    z.h = x.h + n.h;
    if (z.l < x.l) z.h++;
    return z;
}

static uxlen_t uxlen_from_u(uint64_t x) {
    uxlen_t z;
    z.l = x;
    z.h = 0;
    return z;
}

static uxlen_t uxlen_from_i(int64_t x) {
    uxlen_t z;
    z.l = x;
    z.h = x < 0 ? (int64_t)-1 : 0;
    return z;
}

static uxlen_t uxlen_from_u2(uint64_t x, uint64_t y) {
    uxlen_t z;
    z.l = x;
    z.h = y;
    return z;
}

#define uxlen_to_l(x) ((x).l)
#define uxlen_to_h(x) ((x).h)
#define uxlen_add_u(x, y) uxlen_add(x, uxlen_from_u(y))
#define uxlen_add_i(x, y) uxlen_add(x, uxlen_from_i(y))

static uxlen_t uxlen_sll(uxlen_t x, unsigned y) {
    uxlen_t z;
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
    return z;
}

static uxlen_t uxlen_srl(uxlen_t x, unsigned y) {
    uxlen_t z;
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
    return z;
}

static uxlen_t uxlen_sra(uxlen_t x, unsigned y) {
    uxlen_t z;
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
    return z;
}

static uxlen_t uxlen_and(uxlen_t x, uxlen_t y) {
    uxlen_t z;
    z.l = x.l & y.l;
    z.h = x.h & y.h;
    return z;
}

static uxlen_t uxlen_xor(uxlen_t x, uxlen_t y) {
    uxlen_t z;
    z.l = x.l ^ y.l;
    z.h = x.h ^ y.h;
    return z;
}

static uxlen_t uxlen_or(uxlen_t x, uxlen_t y) {
    uxlen_t z;
    z.l = x.l | y.l;
    z.h = x.h | y.h;
    return z;
}
