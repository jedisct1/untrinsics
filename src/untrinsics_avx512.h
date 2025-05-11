/*
 * Untrinsics - Header-only portable implementations of common Intel intrinsics
 * for cryptographic implementations.
 * https://github.com/jedisct1/untrinsics
 * (C) 2025 Frank Denis <j [at] pureftpd.org> - Public Domain.
 */

#ifndef untrinsics_avx512_H
#define untrinsics_avx512_H

#define __untrinsics_avx512__ 1

#include <stdint.h>
#ifndef __untrinsics__ /* untrinsics.h */
#    if defined(__AES__) || (defined(_MSC_VER) && defined(__AVX__))
#        include <smmintrin.h>
#        include <wmmintrin.h>
#    else
#        include "untrinsics.h"
#    endif
#endif

#ifndef __has_attribute
#    define __has_attribute(x) 0
#endif
#if !(__has_attribute(aligned) || defined(__GNUC__) || defined(__clang__) || defined(__attribute__))
#    define __attribute__(x)
#endif

#define __m512i untrinsics__m512i

typedef struct {
    __m128i a, b, c, d;
} __m512i __attribute__((aligned(64)));

#undef _mm512_setr_epi32
#define _mm512_setr_epi32 untrinsics__mm512_setr_epi32
/* build a “512-bit” vector from 16 ints in register order */
static inline __m512i
_mm512_setr_epi32(int e0, int e1, int e2, int e3, int e4, int e5, int e6, int e7, int e8, int e9,
                  int e10, int e11, int e12, int e13, int e14, int e15)
{
    __m512i r;
    r.a = _mm_setr_epi32(e0, e1, e2, e3);
    r.b = _mm_setr_epi32(e4, e5, e6, e7);
    r.c = _mm_setr_epi32(e8, e9, e10, e11);
    r.d = _mm_setr_epi32(e12, e13, e14, e15);
    return r;
}

#undef _mm512_loadu_si512
#define _mm512_loadu_si512 untrinsics__mm512_loadu_si512
/* unaligned load of 64 bytes into our fake-512-bit type: */
static inline __m512i
_mm512_loadu_si512(const void *ptr)
{
    const char *p = (const char *) ptr;
    __m512i     r;
    r.a = _mm_loadu_si128((const __m128i *) (p + 0));
    r.b = _mm_loadu_si128((const __m128i *) (p + 16));
    r.c = _mm_loadu_si128((const __m128i *) (p + 32));
    r.d = _mm_loadu_si128((const __m128i *) (p + 48));
    return r;
}

#undef _mm512_storeu_si512
#define _mm512_storeu_si512 untrinsics__mm512_storeu_si512
/* Store (“unaligned”) our fake-512-bit vector back to memory: */
static inline void
_mm512_storeu_si512(void *ptr, __m512i v)
{
    char *p = (char *) ptr;
    _mm_storeu_si128((__m128i *) (p + 0), v.a);
    _mm_storeu_si128((__m128i *) (p + 16), v.b);
    _mm_storeu_si128((__m128i *) (p + 32), v.c);
    _mm_storeu_si128((__m128i *) (p + 48), v.d);
}

#undef _mm512_xor_si512
#define _mm512_xor_si512 untrinsics__mm512_xor_si512
/* Bitwise XOR of two “512-bit” vectors: */
static inline __m512i
_mm512_xor_si512(__m512i x, __m512i y)
{
    __m512i r;
    r.a = _mm_xor_si128(x.a, y.a);
    r.b = _mm_xor_si128(x.b, y.b);
    r.c = _mm_xor_si128(x.c, y.c);
    r.d = _mm_xor_si128(x.d, y.d);
    return r;
}

#undef _mm512_or_si512
#define _mm512_or_si512 untrinsics__mm512_or_si512
/* Bitwise OR of two “512-bit” vectors (4×128-bit lanes) */
static inline __m512i
_mm512_or_si512(__m512i x, __m512i y)
{
    __m512i r;
    r.a = _mm_or_si128(x.a, y.a);
    r.b = _mm_or_si128(x.b, y.b);
    r.c = _mm_or_si128(x.c, y.c);
    r.d = _mm_or_si128(x.d, y.d);
    return r;
}

#undef _mm512_and_si512
#define _mm512_and_si512 untrinsics__mm512_and_si512
/* Bitwise AND of two “512-bit” vectors (4×128-bit lanes) */
static inline __m512i
_mm512and_si512(__m512i x, __m512i y)
{
    __m512i r;
    r.a = _mm_and_si128(x.a, y.a);
    r.b = _mm_and_si128(x.b, y.b);
    r.c = _mm_and_si128(x.c, y.c);
    r.d = _mm_and_si128(x.d, y.d);
    return r;
}

#undef _mm512_aesenc_epi128
#define _mm512_aesenc_epi128 untrinsics__mm512_aesenc_epi128
/* One AESENC round on each 128-bit lane of a 512-bit vector: */
static inline __m512i
_mm512_aesenc_epi128(__m512i state, __m512i roundkey)
{
    __m512i r;
    r.a = _mm_aesenc_si128(state.a, roundkey.a);
    r.b = _mm_aesenc_si128(state.b, roundkey.b);
    r.c = _mm_aesenc_si128(state.c, roundkey.c);
    r.d = _mm_aesenc_si128(state.d, roundkey.d);
    return r;
}

#undef _mm512_shuffle_i32x4
#define _mm512_shuffle_i32x4 untrinsics__mm512_shuffle_i32x4
/* Shuffle 128-bit lanes of 'a' and 'b' according to imm8:
 *  bits [1:0] → result.a from    a
 *  bits [3:2] → result.b from    a
 *  bits [5:4] → result.c from    b
 *  bits [7:6] → result.d from    b
 */
static inline __m512i
_mm512_shuffle_i32x4(__m512i a, __m512i b, const int imm8)
{
    __m512i r;

    switch (imm8 & 0x3) { /* low 2 bits → r.a from a */
    case 0:
        r.a = a.a;
        break;
    case 1:
        r.a = a.b;
        break;
    case 2:
        r.a = a.c;
        break;
    default:
        r.a = a.d;
        break;
    }
    switch ((imm8 >> 2) & 0x3) { /* bits 3:2 → r.b from a */
    case 0:
        r.b = a.a;
        break;
    case 1:
        r.b = a.b;
        break;
    case 2:
        r.b = a.c;
        break;
    default:
        r.b = a.d;
        break;
    }
    switch ((imm8 >> 4) & 0x3) { /* bits 5:4 → r.c from b */
    case 0:
        r.c = b.a;
        break;
    case 1:
        r.c = b.b;
        break;
    case 2:
        r.c = b.c;
        break;
    default:
        r.c = b.d;
        break;
    }
    switch ((imm8 >> 6) & 0x3) { /* bits 7:6 → r.d from b */
    case 0:
        r.d = b.a;
        break;
    case 1:
        r.d = b.b;
        break;
    case 2:
        r.d = b.c;
        break;
    default:
        r.d = b.d;
        break;
    }
    return r;
}

#undef _mm512_srli_epi32
#define _mm512_srli_epi32 untrinsics__mm512_srli_epi32
/* Logical right shift of each 32-bit element by imm8 */
static inline __m512i
_mm512_srli_epi32(__m512i v, const int imm8)
{
    __m512i r;
    r.a = _mm_srli_epi32(v.a, imm8);
    r.b = _mm_srli_epi32(v.b, imm8);
    r.c = _mm_srli_epi32(v.c, imm8);
    r.d = _mm_srli_epi32(v.d, imm8);
    return r;
}

#undef _mm512_slli_epi32
#define _mm512_slli_epi32 untrinsics__mm512_slli_epi32
/* Logical left shift of each 32-bit element by imm8 */
static inline __m512i
_mm512_slli_epi32(__m512i v, const int imm8)
{
    __m512i r;
    r.a = _mm_slli_epi32(v.a, imm8);
    r.b = _mm_slli_epi32(v.b, imm8);
    r.c = _mm_slli_epi32(v.c, imm8);
    r.d = _mm_slli_epi32(v.d, imm8);
    return r;
}

#endif
