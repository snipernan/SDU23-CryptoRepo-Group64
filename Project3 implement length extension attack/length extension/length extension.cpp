#include<iostream>
#include<chrono>>
#include <thread>
#include <mutex>
#include <iomanip>
#include <sstream>
#include<stdio.h>
#include <openssl/evp.h>
#include <immintrin.h>

#define SM3_DIGEST_LENGTH 32
#define FF0(x, y, z) (_mm256_xor_si256((x), _mm256_xor_si256((y), (z))))
#define FF1(x, y, z) (_mm256_or_si256(_mm256_and_si256(y, z), _mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(x, z))))//(X & Y | X & Z | Y & Z)
#define GG0(x, y, z) (_mm256_xor_si256((x), _mm256_xor_si256((y), (z))))
#define GG1(x, y, z) (_mm256_or_si256(_mm256_and_si256(x, y), _mm256_and_si256(_mm256_andnot_si256(x, _mm256_set1_epi32(-1)), z)))//(X & Y | ~X & Z)
#define P00(x) (_mm256_xor_si256(_mm256_xor_si256((x), ROTL(x, 9)),ROTL(x, 17)))
#define P10(x) (_mm256_xor_si256(_mm256_xor_si256((x), ROTL(x, 15)),ROTL(x, 23)))

#define ROTL(x, n) (_mm256_or_si256(_mm256_slli_epi32((x), (n)), _mm256_srli_epi32((x), 32 - (n))))
using namespace std;

static const uint32_t IV[8] = { 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e };

inline uint32_t T(uint32_t j) {
	return (j < 16) ? 0x79cc4519 : 0x7a879d8a;
}

inline uint32_t FF(uint32_t j, uint32_t X, uint32_t Y, uint32_t Z) {
	return (j < 16) ? (X ^ Y ^ Z) : (X & Y | X & Z | Y & Z);
}

inline uint32_t GG(uint32_t j, uint32_t X, uint32_t Y, uint32_t Z) {
	return (j < 16) ? (X ^ Y ^ Z) : (X & Y | ~X & Z);
}

inline uint32_t P0(uint32_t x) {
	return x ^ (x << 9 | x >> (32 - 9)) ^ (x << 17 | x >> (32 - 17));
}

inline uint32_t P1(uint32_t x) {
	return x ^ (x << 15 | x >> (32 - 15)) ^ (x << 23 | x >> (32 - 23));
}

uint8_t* padding(uint8_t* m, int l) {
	int r = l % 64;
	int new_l;
	uint8_t* padded_m;

	if (r < 56) {
		new_l = l - r + 64;
	}
	else {
		new_l = l - r + 128;
	}

	padded_m = (uint8_t*)malloc(new_l);
	memcpy(padded_m, m, l);
	memset(padded_m + l, 0, new_l - l - 8);
	padded_m[l] = 0x80;
	uint64_t bit_len = (uint64_t)l * 8;
	uint8_t buf[8];
	for (int i = 0; i < 8; i++) {
		buf[i] = (bit_len >> ((7 - i) * 8)) & 0xff;
	}
	memcpy(padded_m + new_l - 8, &buf, 8);
	return padded_m;
}

uint32_t le32toh(uint32_t x) {
	return ((x & 0xff) << 24) |
		((x & 0xff00) << 8) |
		((x & 0xff0000) >> 8) |
		((x & 0xff000000) >> 24);
}


__m256i rotl(__m256i v, int n) {
	__m256i mask = _mm256_set_epi32(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, (1 << n) - 1);
	__m256i rotated = _mm256_slli_epi32(v, n);
	rotated = _mm256_and_si256(rotated, mask);
	return rotated;
}

void sm3_compress_avx2(const uint8_t* m, uint32_t V[8]) {
	int n = strlen((char*)m) / 64;
	for (int j = 0; j <= n; j++) {
		__m256i A = _mm256_set1_epi32(V[0]);
		__m256i B = _mm256_set1_epi32(V[1]);
		__m256i C = _mm256_set1_epi32(V[2]);
		__m256i D = _mm256_set1_epi32(V[3]);
		__m256i E = _mm256_set1_epi32(V[4]);
		__m256i F = _mm256_set1_epi32(V[5]);
		__m256i G = _mm256_set1_epi32(V[6]);
		__m256i H = _mm256_set1_epi32(V[7]);

		__m256i W[68];
		for (int i = 0; i < 16; i++) {
			__m256i w = _mm256_loadu_si256((__m256i*)(m + j *64 + i * 4 * sizeof(uint8_t)));
			W[i] = _mm256_shuffle_epi8(w, _mm256_set_epi32(0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00010203));
		}

		for (int i = 16; i < 68; i++) {
			__m256i w1 = W[i - 16];
			__m256i w2 = W[i - 9];
			__m256i w3 = ROTL(W[i - 3], 15);
			__m256i w4 = _mm256_xor_si256(w1, w2);
			__m256i w5 = _mm256_xor_si256(w4, w3);
			__m256i w6 = P10(w5);
			__m256i w7 = _mm256_xor_si256(w6, ROTL(W[i - 13], 7));
			W[i] = _mm256_xor_si256(w7, W[i - 6]);

		}

		__m256i W0[64];
		for (int i = 0; i < 64; i++) {
			W0[i] = _mm256_xor_si256(W[i], W[i + 4]);
		}

		for (int i = 0; i < 16; i++) {
			__m256i SS1_0 = _mm256_add_epi32(ROTL(A, 12), E);
			__m256i SS1_1 = _mm256_add_epi32(SS1_0, ROTL(_mm256_set1_epi32(T(i)), i));
			__m256i SS1 = ROTL(SS1_1, 7);

			__m256i SS2 = _mm256_xor_si256(SS1, ROTL(A, 12));

			__m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF0(A, B, C), D), SS2), W0[i]);
			__m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG0(E, F, G), H), SS1), W[i]);
			D = C;
			C = _mm256_or_si256(ROTL(B, 9), _mm256_srli_epi32(B, 23));
			B = A;
			A = TT1;
			H = G;
			G = _mm256_or_si256(ROTL(F, 19), _mm256_srli_epi32(F, 13));
			F = E;
			E = P00(TT2);
		}
		for (int i = 16; i < 64; i++) {
			__m256i SS1_0 = _mm256_add_epi32(ROTL(A, 12), E);
			__m256i SS1_1 = _mm256_add_epi32(SS1_0, ROTL(_mm256_set1_epi32(T(i)), i%32));
			__m256i SS1 = ROTL(SS1_1, 7);

			__m256i SS2 = _mm256_xor_si256(SS1, ROTL(A, 12));
			__m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF1(A, B, C), D), SS2), W0[i]);
			__m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG1(E, F, G), H), SS1), W[i]);
			D = C;
			C = _mm256_or_si256(ROTL(B, 9), _mm256_srli_epi32(B, 23));
			B = A;
			A = TT1;
			H = G;
			G = _mm256_or_si256(ROTL(F, 19), _mm256_srli_epi32(F, 13));
			F = E;
			E = P00(TT2);
		}


		V[0] ^= _mm256_extract_epi32(A, 0) ;
		V[1] ^= _mm256_extract_epi32(B, 0) ;
		V[2] ^= _mm256_extract_epi32(C, 0) ;
		V[3] ^= _mm256_extract_epi32(D, 0) ;
		V[4] ^= _mm256_extract_epi32(E, 0) ;
		V[5] ^= _mm256_extract_epi32(F, 0) ;
		V[6] ^= _mm256_extract_epi32(G, 0) ;
		V[7] ^= _mm256_extract_epi32(H, 0) ;
	}
}


void iterate(uint8_t* m, uint32_t* V) {
	int n = strlen((char*)m) / 64;
	uint32_t B[16];
	for (int i = 0; i <= n; i++) {
		for (int j = 0; j < 16; j++) {
			// 将每个 32 位字的字节序进行反转
			B[j] = le32toh(((uint32_t*)m)[i * 16 + j]);
		}
		uint32_t A = V[0], B1 = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
		uint32_t W[68];
		for (int j = 0; j < 16; j++) {
			W[j] = B[j];
		}
		for (int j = 16; j < 68; j++) {
			W[j] = P1(W[j - 16] ^ W[j - 9] ^ (W[j - 3] << 15 | W[j - 3] >> (32 - 15))) ^ (W[j - 13] << 7 | W[j - 13] >> (32 - 7)) ^ W[j - 6];
		}
		uint32_t W0[64];
		for (int j = 0; j < 64; j++) {
			W0[j] = W[j] ^ W[j + 4];
		}
		uint32_t SS1_0, SS1, SS2, TT1, TT2;
		for (int j = 0; j < 64; j++) {
			SS1_0 = (A << 12 | A >> (32 - 12)) + E + ((T(j) << j) | T(j) >> (32 - j));
			SS1 = (SS1_0 << 7 | SS1_0 >> (32 - 7));
			SS2 = SS1 ^ (A << 12 | A >> (32 - 12));
			TT1 = FF(j, A, B1, C) + D + SS2 + W0[j];
			TT2 = GG(j, E, F, G) + H + SS1 + W[j];
			D = C;
			C = (B1 << 9 | B1 >> (32 - 9));
			B1 = A;
			A = TT1;
			H = G;
			G = (F << 19 | F >> (32 - 19));
			F = E;
			E = P0(TT2);
		}
		V[0] ^= A, V[1] ^= B1, V[2] ^= C, V[3] ^= D, V[4] ^= E, V[5] ^= F, V[6] ^= G, V[7] ^= H;
	}
}

void sm3(uint8_t* m, int l, uint32_t* result) {
	m = padding(m, l);
	iterate(m, result);
}


// 计算哈希值
void openssl_sm3(const unsigned char* msg, size_t msglen, unsigned char dgst[SM3_DIGEST_LENGTH]) {
	uint32_t out_size = SM3_DIGEST_LENGTH;
	EVP_Digest(msg, msglen, dgst, &out_size, EVP_sm3(), nullptr);
}

void length_extension_attack(uint32_t* original_hash, int original_length, uint8_t* extension_message, int extension_length, uint32_t* extension_hash) {
	memcpy(extension_hash, original_hash, sizeof(original_hash));
	sm3(extension_message, extension_length, extension_hash);
}

int main() {
	// 输入消息
	const int MESSAGE_SIZE = 64; //单位是字节

	uint8_t msg1[64] = { 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64};

	
	uint32_t result[8];

	auto start = chrono::high_resolution_clock::now();
	for (int i = 0; i < 1; i++) {
		memcpy(result, IV, sizeof(IV));
		sm3(msg1, sizeof(msg1), result);
	}
	auto end = chrono::high_resolution_clock::now();
	cout << endl << "Hash(input): ";
	for (int i = 0; i < 8; i++) {
		cout << hex << result[i];
	}
	cout << endl;

	// 输出时间
	auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
	cout << "优化版SM3计算时间为：" << dec << duration.count() << " 微秒" << endl;

	uint8_t original_message[64] = { 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64 };
	int original_length = sizeof(original_message);
	uint32_t original_hash[8];
	memcpy(original_hash, IV, sizeof(IV));
	sm3(original_message, original_length, original_hash);

	uint8_t extension_message[1] = {0x65};
	int extension_length = sizeof(extension_message);
	uint32_t extension_hash[8];
	length_extension_attack(original_hash, original_length, extension_message, extension_length, extension_hash);

	printf("Original hash: ");
	for (int i = 0; i < 8; i++) {
		printf("%08x ", original_hash[i]);
	}
	printf("\n");

	printf("Extended message:%02x\n", extension_message[0]);
	printf("Extended hash: ");
	for (int i = 0; i < 8; i++) {
		printf("%08x ", extension_hash[i]);
	}
	printf("\n");

	return 0;
}

