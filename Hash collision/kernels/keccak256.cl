#define OPENCL_PLATFORM_UNKNOWN 0
#define OPENCL_PLATFORM_AMD   2

#ifndef PLATFORM
# define PLATFORM       OPENCL_PLATFORM_UNKNOWN
#endif

#if PLATFORM == OPENCL_PLATFORM_AMD
# pragma OPENCL EXTENSION   cl_amd_media_ops : enable
#endif

typedef union _nonce_t
{
  ulong   uint64_t;
  uint    uint32_t[2];
  uchar   uint8_t[8];
} nonce_t;

#if PLATFORM == OPENCL_PLATFORM_AMD
static inline ulong rol(const ulong x, const uint s)
{
  uint2 output;
  uint2 x2 = as_uint2(x);

  output = (s > 32u) ? amd_bitalign((x2).yx, (x2).xy, 64u - s) : amd_bitalign((x2).xy, (x2).yx, 32u - s);
  return as_ulong(output);
}
#else
#define rol(x, s) (((x) << s) | ((x) >> (64u - s)))
#endif

#define rol1(x) rol(x, 1u)

#define theta_(m, n, o) \
t = b[m] ^ rol1(b[n]); \
a[o + 0] ^= t; \
a[o + 5] ^= t; \
a[o + 10] ^= t; \
a[o + 15] ^= t; \
a[o + 20] ^= t; \

#define theta() \
b[0] = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]; \
b[1] = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]; \
b[2] = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]; \
b[3] = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]; \
b[4] = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]; \
theta_(4, 1, 0); \
theta_(0, 2, 1); \
theta_(1, 3, 2); \
theta_(2, 4, 3); \
theta_(3, 0, 4);

#define rhoPi_(m, n) t = b[0]; b[0] = a[m]; a[m] = rol(t, n); \

#define rhoPi() t = a[1]; b[0] = a[10]; a[10] = rol1(t); \
rhoPi_(7, 3); \
rhoPi_(11, 6); \
rhoPi_(17, 10); \
rhoPi_(18, 15); \
rhoPi_(3, 21); \
rhoPi_(5, 28); \
rhoPi_(16, 36); \
rhoPi_(8, 45); \
rhoPi_(21, 55); \
rhoPi_(24, 2); \
rhoPi_(4, 14); \
rhoPi_(15, 27); \
rhoPi_(23, 41); \
rhoPi_(19, 56); \
rhoPi_(13, 8); \
rhoPi_(12, 25); \
rhoPi_(2, 43); \
rhoPi_(20, 62); \
rhoPi_(14, 18); \
rhoPi_(22, 39); \
rhoPi_(9, 61); \
rhoPi_(6, 20); \
rhoPi_(1, 44);

#define chi_(n) \
b[0] = a[n + 0]; \
b[1] = a[n + 1]; \
b[2] = a[n + 2]; \
b[3] = a[n + 3]; \
b[4] = a[n + 4]; \
a[n + 0] = b[0] ^ ((~b[1]) & b[2]); \
a[n + 1] = b[1] ^ ((~b[2]) & b[3]); \
a[n + 2] = b[2] ^ ((~b[3]) & b[4]); \
a[n + 3] = b[3] ^ ((~b[4]) & b[0]); \
a[n + 4] = b[4] ^ ((~b[0]) & b[1]);

#define chi() chi_(0); chi_(5); chi_(10); chi_(15); chi_(20);

#define iota(x) a[0] ^= x;

#define iteration(x) theta(); rhoPi(); chi(); iota(x);

static inline void keccakf(ulong *a)
{
  ulong b[5];
  ulong t;

  iteration(0x0000000000000001); // iteration 1
  iteration(0x0000000000008082); // iteration 2
  iteration(0x800000000000808a); // iteration 3
  iteration(0x8000000080008000); // iteration 4
  iteration(0x000000000000808b); // iteration 5
  iteration(0x0000000080000001); // iteration 6
  iteration(0x8000000080008081); // iteration 7
  iteration(0x8000000000008009); // iteration 8
  iteration(0x000000000000008a); // iteration 9
  iteration(0x0000000000000088); // iteration 10
  iteration(0x0000000080008009); // iteration 11
  iteration(0x000000008000000a); // iteration 12
  iteration(0x000000008000808b); // iteration 13
  iteration(0x800000000000008b); // iteration 14
  iteration(0x8000000000008089); // iteration 15
  iteration(0x8000000000008003); // iteration 16
  iteration(0x8000000000008002); // iteration 17
  iteration(0x8000000000000080); // iteration 18
  iteration(0x000000000000800a); // iteration 19
  iteration(0x800000008000000a); // iteration 20
  iteration(0x8000000080008081); // iteration 21
  iteration(0x8000000000008080); // iteration 22
  iteration(0x0000000080000001); // iteration 23
  iteration(0x8000000080008008); // iteration 24

}

static inline bool hasLeading(uchar const *d)
{
  ulong prefixBuffer[25];
#define prefix ((uchar *) prefixBuffer)
  prefix[1] = S_1;
  prefix[2] = S_2;
  prefix[3] = S_3;
  prefix[4] = S_4;
  prefix[5] = S_5;
  prefix[6] = S_6;
  prefix[7] = S_7;
  prefix[8] = S_8;
  prefix[9] = S_9;
  prefix[10] = S_10;
  prefix[11] = S_11;
  prefix[12] = S_12;
  prefix[13] = S_13;
  prefix[14] = S_14;
  prefix[15] = S_15;
  prefix[16] = S_16;
  prefix[17] = S_17;
  prefix[18] = S_18;
  prefix[19] = S_19;
  prefix[20] = S_20;
  prefix[21]=S_21;
  prefix[22]=S_22;
  prefix[23]=S_23;
  prefix[24]=S_24;
  prefix[25]=S_25;
  prefix[26]=S_26;
  prefix[27]=S_27;
  prefix[28]=S_28;
  prefix[29]=S_29;
  prefix[30]=S_30;
  prefix[31]=S_31;
  prefix[32]=S_32;

  uint len=LEADING_ZEROES/2;
  for (uint i = 0; i < len; ++i) {
    if (d[i] != prefix[i+1]) return false;
  }
  if(LEADING_ZEROES%2==1){
    uchar target=prefix[len+1]& 0xf0u;
    uchar origin=d[len] & 0xf0u;
    if(target!=origin){
      return false;
    }

  }
    if(d[len]==prefix[len+1]){
      return false;
    }
  return true;
}

__kernel void hashMessage(
  __constant uchar const *d_message,
  __constant uint const *d_nonce,
  __global volatile ulong *restrict solutions
) {

  ulong spongeBuffer[25];

#define sponge ((uchar *) spongeBuffer)

  nonce_t nonce;
  nonce.uint32_t[0] = d_nonce[0];
  nonce.uint32_t[1] = get_global_id(0);

  #pragma unroll
  for (int i =0; i < 12; ++i)
    sponge[i] = d_message[i];
  #pragma unroll
  for (int i =12; i < 20; ++i)
    sponge[i] = nonce.uint8_t[i-12];
  
  #pragma unroll
  for (int i =20; i <200; ++i)
    sponge[i] = 0;

  sponge[20] =0x1;

  sponge[135] =0x80;

  keccakf(spongeBuffer);

  if (hasLeading(sponge)) {
    solutions[0] = nonce.uint64_t;
  }
}
