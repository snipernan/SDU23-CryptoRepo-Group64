#include<iostream>
#include<chrono>>
#include <thread>
#include <mutex>
#include <iomanip>
#include <sstream>
#include<stdio.h>
#include <openssl/evp.h>

#define SM3_DIGEST_LENGTH 32
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

void iterate(uint8_t* m, uint32_t* V) {
	int n = strlen((char*)m) / 64;
	uint32_t B[16];
	    for (int i = 0; i <=n; i++) {
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

void testSM3() {
	// 输入消息
	const int MESSAGE_SIZE = 64; //单位是字节
	int message[MESSAGE_SIZE] = { 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
								0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64 };

	uint8_t msg1[64] = { 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
					 0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64 };

	// 初始化输出哈希值
	int hash[8] = { 0 };
	char msg[] = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
	unsigned char dgst[SM3_DIGEST_LENGTH];
	uint32_t out_size = 32;
	// 计时
	auto start = chrono::high_resolution_clock::now();
	EVP_Digest(msg1, 64, dgst, &out_size, EVP_sm3(), nullptr);
	auto end = chrono::high_resolution_clock::now();

	printf("SM3 哈希值为：");
	for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
		printf("%02x", dgst[i]);
	}
	printf("\n");

	// 输出时间
	auto duration = chrono::duration_cast<chrono::microseconds>(end - start);
	cout << "openssl通用Digest接口计算时间为：" << dec << duration.count() << " 微秒" << endl;



	// 使用 OpenSSL 计算 SM3 哈希值
	cout << endl;
	uint8_t pre_hash[32];
	start = chrono::high_resolution_clock::now();
	EVP_MD_CTX* mdctx;
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
	EVP_DigestUpdate(mdctx, msg1, 64);
	EVP_DigestFinal_ex(mdctx, pre_hash, NULL);
	end = chrono::high_resolution_clock::now();
	// 输出 SM3 哈希值
	cout << "Hash(input): ";
	for (int i = 0; i < EVP_MD_size(EVP_sm3()); i++) {
		cout << hex << setw(2) << setfill('0') << (int)pre_hash[i];
	}
	cout << endl;
	// 输出时间
	duration = chrono::duration_cast<chrono::microseconds>(end - start);
	cout << "openssl底层接口计算时间为：" << dec << duration.count() << " 微秒" << endl;


	// Measure time

	uint32_t result[8];
	memcpy(result, IV, sizeof(IV));
	start = chrono::high_resolution_clock::now();
	sm3(msg1, sizeof(msg1), result);
	end = chrono::high_resolution_clock::now();
	cout << endl << "Hash(input): ";
	for (int i = 0; i < 8; i++) {
		cout << hex << result[i];
	}
	cout << endl;

	// 输出时间
	duration = chrono::duration_cast<chrono::microseconds>(end - start);
	cout << "优化版SM3计算时间为：" << dec<< duration.count() << " 微秒" << endl;
}

int main() {
	testSM3();
}

