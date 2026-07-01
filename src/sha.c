/* Pure C SHA-256/384/512 implementation.
 * Based on FIPS 180-4. No external dependencies.
 */

#include "sha.h"
#include <string.h>

/* ---- SHA-256 ---- */

#define ROR32(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0_256(x) (ROR32(x,2)^ROR32(x,13)^ROR32(x,22))
#define EP1_256(x) (ROR32(x,6)^ROR32(x,11)^ROR32(x,25))
#define SIG0_256(x)(ROR32(x,7)^ROR32(x,18)^((x)>>3))
#define SIG1_256(x)(ROR32(x,17)^ROR32(x,19)^((x)>>10))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_block(uint32_t *h, const uint8_t *blk) {
    uint32_t w[64], a,b,c,d,e,f,g,hh,t1,t2;
    int i;
    for(i=0;i<16;i++) w[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|((uint32_t)blk[i*4+2]<<8)|blk[i*4+3];
    for(i=16;i<64;i++) w[i]=SIG1_256(w[i-2])+w[i-7]+SIG0_256(w[i-15])+w[i-16];
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for(i=0;i<64;i++){
        t1=hh+EP1_256(e)+CH(e,f,g)+K256[i]+w[i];
        t2=EP0_256(a)+MAJ(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

void n2n_sha256(const uint8_t *data, size_t len, uint8_t *digest) {
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t buf[64];
    size_t i, rem=len&63;
    uint64_t bits=(uint64_t)len*8;
    for(i=0;i+64<=len;i+=64) sha256_block(h,data+i);
    memcpy(buf,data+i,rem);
    buf[rem]=0x80;
    if(rem>=56){memset(buf+rem+1,0,63-rem);sha256_block(h,buf);memset(buf,0,56);}
    else memset(buf+rem+1,0,55-rem);
    for(i=0;i<8;i++) buf[56+i]=(uint8_t)(bits>>((7-i)*8));
    sha256_block(h,buf);
    for(i=0;i<8;i++){digest[i*4]=(uint8_t)(h[i]>>24);digest[i*4+1]=(uint8_t)(h[i]>>16);digest[i*4+2]=(uint8_t)(h[i]>>8);digest[i*4+3]=(uint8_t)h[i];}
}

/* ---- SHA-512 (and SHA-384 as truncated SHA-512) ---- */

#define ROR64(x,n) (((x)>>(n))|((x)<<(64-(n))))
#define CH64(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ64(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0_512(x) (ROR64(x,28)^ROR64(x,34)^ROR64(x,39))
#define EP1_512(x) (ROR64(x,14)^ROR64(x,18)^ROR64(x,41))
#define SIG0_512(x)(ROR64(x,1)^ROR64(x,8)^((x)>>7))
#define SIG1_512(x)(ROR64(x,19)^ROR64(x,61)^((x)>>6))

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static void sha512_block(uint64_t *h, const uint8_t *blk) {
    uint64_t w[80],a,b,c,d,e,f,g,hh,t1,t2;
    int i;
    for(i=0;i<16;i++){
        w[i]=((uint64_t)blk[i*8]<<56)|((uint64_t)blk[i*8+1]<<48)|((uint64_t)blk[i*8+2]<<40)|((uint64_t)blk[i*8+3]<<32)|
             ((uint64_t)blk[i*8+4]<<24)|((uint64_t)blk[i*8+5]<<16)|((uint64_t)blk[i*8+6]<<8)|blk[i*8+7];
    }
    for(i=16;i<80;i++) w[i]=SIG1_512(w[i-2])+w[i-7]+SIG0_512(w[i-15])+w[i-16];
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for(i=0;i<80;i++){
        t1=hh+EP1_512(e)+CH64(e,f,g)+K512[i]+w[i];
        t2=EP0_512(a)+MAJ64(a,b,c);
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void sha512_common(const uint8_t *data, size_t len, uint8_t *digest, int is384) {
    uint64_t h[8];
    uint8_t buf[128];
    size_t i, rem=len&127;
    uint64_t bits_hi=0, bits_lo=(uint64_t)len*8;

    if(is384){
        h[0]=0xcbbb9d5dc1059ed8ULL;h[1]=0x629a292a367cd507ULL;h[2]=0x9159015a3070dd17ULL;h[3]=0x152fecd8f70e5939ULL;
        h[4]=0x67332667ffc00b31ULL;h[5]=0x8eb44a8768581511ULL;h[6]=0xdb0c2e0d64f98fa7ULL;h[7]=0x47b5481dbefa4fa4ULL;
    } else {
        h[0]=0x6a09e667f3bcc908ULL;h[1]=0xbb67ae8584caa73bULL;h[2]=0x3c6ef372fe94f82bULL;h[3]=0xa54ff53a5f1d36f1ULL;
        h[4]=0x510e527fade682d1ULL;h[5]=0x9b05688c2b3e6c1fULL;h[6]=0x1f83d9abfb41bd6bULL;h[7]=0x5be0cd19137e2179ULL;
    }

    for(i=0;i+128<=len;i+=128) sha512_block(h,data+i);
    memcpy(buf,data+i,rem);
    buf[rem]=0x80;
    if(rem>=112){memset(buf+rem+1,0,127-rem);sha512_block(h,buf);memset(buf,0,112);}
    else memset(buf+rem+1,0,111-rem);
    for(i=0;i<8;i++) buf[112+i]=(uint8_t)(bits_hi>>((7-i)*8));
    for(i=0;i<8;i++) buf[120+i]=(uint8_t)(bits_lo>>((7-i)*8));
    sha512_block(h,buf);

    int out_words = is384 ? 6 : 8;
    for(i=0;i<(size_t)out_words;i++){
        digest[i*8]=(uint8_t)(h[i]>>56);digest[i*8+1]=(uint8_t)(h[i]>>48);
        digest[i*8+2]=(uint8_t)(h[i]>>40);digest[i*8+3]=(uint8_t)(h[i]>>32);
        digest[i*8+4]=(uint8_t)(h[i]>>24);digest[i*8+5]=(uint8_t)(h[i]>>16);
        digest[i*8+6]=(uint8_t)(h[i]>>8);digest[i*8+7]=(uint8_t)h[i];
    }
}

void n2n_sha384(const uint8_t *data, size_t len, uint8_t *digest) { sha512_common(data,len,digest,1); }
void n2n_sha512(const uint8_t *data, size_t len, uint8_t *digest) { sha512_common(data,len,digest,0); }
