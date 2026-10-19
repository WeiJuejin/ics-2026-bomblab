#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}


int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;

    uint32_t x = (uint32_t)challenge;
    uint32_t h = (uint32_t)(challenge >> 32);
    uint32_t m = (uint32_t)(challenge >> 16);

    uint32_t a = (h + 0x802bU) ^ x;
    uint32_t b = (5U * h + m) ^ 0x8496U;
    uint32_t c = 5U * (b - x) + 0xd8b7U;

    values[0] = c ^ a;
    count = 1;

    return write_answer(out, cap, values, count);
}


int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    /* 第一个整数 */
    values[0] = (uint32_t)((challenge >> 16) & 0x1fU) + 1U;

    /* 计算第二至第六个整数 */
    for (uint32_t i = 1; i < 6; ++i) {
        uint32_t shift = 5U + 4U * (i - 1U);
        uint32_t bits = (uint32_t)((challenge >> shift) & 0x1fU);

        uint32_t prev = 3U * values[i - 1U];

        values[i] = (bits + i) ^ prev;
    }

    return write_answer(out, cap, values, 6);
}


int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    uint32_t branch = (uint32_t)(challenge & 0x7U);
    uint32_t x = (uint32_t)(challenge >> 3)
               ^ (uint32_t)(challenge >> 32);
    uint32_t result;

    switch (branch) {
        case 0:
            result = (4U * x) ^ 0xf50cU;
            break;
        case 1:
            result = 5U * x + 0x1e555U;
            break;
        case 2:
            result = 5U * x + 0x33ac2U;
            break;
        case 3:
            result = 3U * x + 0x90bbU;
            break;
        case 4:
            result = 5U * x + 0xaaa6U;
            break;
        case 5:
            result = (x ^ 0x7e81U) + (x >> 1);
            break;
        case 6:
            result = (x ^ 0x4b8aU) + (x >> 1);
            break;
        case 7:
            result = (2U * x) ^ 0x813dU;
            break;
        default:
            return 1;
    }

    values[0] = branch;
    values[1] = result;

    return write_answer(out, cap, values, 2);
}

static uint32_t p4_walk(uint32_t target,
                        uint32_t low,
                        uint32_t high,
                        uint32_t salt) {
    uint32_t mid = low + (high - low) / 2U;

    if (target == mid) {
        return (mid + 0xb8U) ^ salt;
    }

    uint32_t child;
    uint32_t result = 3U;

    if (target < mid) {
        child = p4_walk(target, low, mid - 1U, salt);
        result *= child;
        result ^= mid + salt;
        result ^= 0x1aU;
    } else {
        child = p4_walk(target, mid + 1U, high, salt);
        result *= child;
        result ^= mid + salt;
        result ^= 0x0dU;
    }

    return result;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    uint32_t target = (uint32_t)(challenge & 0x7fU);
    uint32_t salt = (uint32_t)(challenge >> 7)
                  ^ (uint32_t)(challenge >> 32);

    values[0] = p4_walk(target, 0U, 127U, salt);

    return write_answer(out, cap, values, 1);
}


typedef struct {
    uint32_t value;
    uint32_t output;
    uint32_t next;
} P5Node;

static const P5Node p5_nodes[12] = {
    {0xf539U, 0x0550U, 4U},  /* 0x405ba0 */
    {0x751bU, 0x033bU, 11U}, /* 0x405bb0 */
    {0xb116U, 0x067fU, 0U},  /* 0x405bc0 */
    {0xaa1bU, 0x0a64U, 12U}, /* 0x405bd0 */
    {0x5a00U, 0x0004U, 9U},  /* 0x405be0 */
    {0xa30cU, 0x072eU, 3U},  /* 0x405bf0 */
    {0x65bdU, 0x097dU, 1U},  /* 0x405c00 */
    {0xf5e8U, 0x010cU, 2U},  /* 0x405c10 */
    {0xd2f4U, 0x0879U, 5U},  /* 0x405c20 */
    {0x935bU, 0x0416U, 8U},  /* 0x405c30 */
    {0x426bU, 0x0b4cU, 6U},  /* 0x405c40 */
    {0xebd0U, 0x022eU, 7U}   /* 0x405c50 */
};

static const uint32_t p5_start[8] = {
    10U, 6U, 1U, 11U, 7U, 2U, 0U, 4U
};

static uint32_t p5_compute(uint64_t challenge, uint32_t *last_output) {
    uint32_t index = p5_start[(uint32_t)(challenge & 7U)];
    uint32_t walk = (uint32_t)((challenge >> 3) & 3U);
    uint32_t count = walk == 0U ? 1U : walk + 1U;

    uint32_t result = (uint32_t)(challenge >> 6)
                    ^ (uint32_t)(challenge >> 32)
                    ^ 0xe284U;

    for (uint32_t i = 0; i < count; ++i) {
        const P5Node *node = &p5_nodes[index];

        result = (result + node->value) * 5U;
        result ^= node->output;
        *last_output = node->output;

        if (i + 1U < count) {
            index = node->next;
        }
    }

    return result;
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    uint32_t last_output = 0;

    values[0] = p5_compute(challenge, &last_output);
    values[1] = last_output;

    return write_answer(out, cap, values, 2);
}

static uint32_t p6_op_0(uint32_t x) {
    return (x >> 7) | (x << 25);
}

static uint32_t p6_op_1(uint32_t x) {
    return (x + 0xca8aU) ^ (x >> 5);
}

static uint32_t p6_op_2(uint32_t x) {
    return (4U * x + 0x1a62U) ^ (5U * x);
}

static uint32_t p6_op_3(uint32_t x) {
    return ((x >> 5) ^ x) + 0x5f6cU;
}

static uint32_t p6_op_4(uint32_t x) {
    return ((x << 3) | (x >> 29)) ^ 0x44feU;
}

static uint32_t p6_op_5(uint32_t x) {
    return (x ^ 0x4165U) + 2U * x;
}

typedef uint32_t (*P6Op)(uint32_t);

static uint32_t p6_compute(uint64_t challenge) {
    static P6Op ops[8] = {
        p6_op_0,
        p6_op_2,
        p6_op_5,
        p6_op_3,
        p6_op_5,
        p6_op_4,
        p6_op_4,
        p6_op_1
    };

    uint32_t a = (uint32_t)(challenge >> 6)
               ^ (uint32_t)(challenge >> 32);

    uint32_t i = (uint32_t)(challenge & 7U);
    uint32_t j = (uint32_t)((challenge >> 3) & 7U);

    uint32_t u = ops[i](a);
    uint32_t v = ops[j](u ^ 0x29b9U);

    return v + 0x2836U;
}

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};

    values[0] = p6_compute(challenge);

    return write_answer(out, cap, values, 1);
}


static uint32_t secret_rol32(uint32_t x, unsigned int n) {
    return (x << n) | (x >> (32U - n));
}

static uint32_t secret_mix_value(uint32_t x) {
    return (secret_rol32(x, 1U) + 0x0fcbU) ^ 0x782bU;
}

int solve_secret(uint64_t challenge, uint64_t context,
                 char *out, size_t cap) {
    uint32_t c_low = (uint32_t)challenge;
    uint32_t c_high = (uint32_t)(challenge >> 32);
    uint32_t k_low = (uint32_t)context;
    uint32_t k_high = (uint32_t)(context >> 32);

    uint32_t x = k_low & 3U;

    uint32_t a = (c_low ^ c_high) ^ (k_low ^ k_high);

    uint32_t b = (x * 0x0fcbU)
               ^ (uint32_t)(context >> 16);

    uint32_t y = secret_mix_value(a) ^ b;

    uint32_t d = (k_low ^ k_high)
               + x
               + 0x782bU
               + ((c_low ^ c_high) >> 1);

    uint32_t z = y ^ d;

    /*
     * secret_gate 要求偏移 32 处为 "OPEN"。
     * %32s 配合空字符串生成 32 个空格，
     * 因而 OPEN 恰好从第 33 个字节开始。
     * secret_phase 随后从 OPEN 后面读取三个整数。
     */
    int n = snprintf(out, cap, "%32sOPEN%u %u %u",
                     "", (unsigned int)x,
                     (unsigned int)y, (unsigned int)z);

    if (n < 0 || (size_t)n >= cap) {
        return 1;
    }

    return 0;
}

