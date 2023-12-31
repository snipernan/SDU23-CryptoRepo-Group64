#include <iostream>
#include <cstring>
#include <windows.h>
using namespace std;
//S盒
unsigned char SBox[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};


unsigned char Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10,
	0x20, 0x40, 0x80, 0x1B, 0x36 };

// x → 2x的查找表
unsigned char mul2[] =
{
	0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
	0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
	0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
	0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
	0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
	0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
	0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
	0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
	0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
	0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
	0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
	0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
	0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
	0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
	0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
	0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
};


//密钥扩展
void KeyExpansion(unsigned char key[], unsigned char roundKey[])
{
	int i;
	for (i = 0; i < 16; i++)
		roundKey[i] = key[i];
	for (i = 1; i < 11; i++)
	{
		roundKey[16*i] = roundKey[(i - 1) * 16] ^ SBox[roundKey[(i - 1)*16 + 13]] ^ Rcon[i - 1];
		roundKey[16 * i+1] = roundKey[(i - 1 )* 16+1] ^ SBox[roundKey[(i - 1) * 16 + 14]];
		roundKey[16 * i+2] = roundKey[(i - 1) * 16 +2] ^ SBox[roundKey[(i - 1) * 16 + 15]];
		roundKey[16 * i+3] = roundKey[(i - 1) * 16 +3] ^ SBox[roundKey[(i - 1) * 16 + 12]];
		roundKey[16 * i+4] = roundKey[(i - 1) * 16 +4] ^ roundKey[i*16];
		roundKey[16 * i+5] = roundKey[(i - 1) * 16 +5] ^ roundKey[i * 16+1];
		roundKey[16 * i+6] = roundKey[(i - 1) * 16 +6] ^ roundKey[i * 16 + 2];
		roundKey[16 * i+7] = roundKey[(i - 1) * 16 + 7] ^ roundKey[i * 16 + 3];
		roundKey[16 * i+8] = roundKey[(i - 1) * 16 + 8] ^ roundKey[i * 16 + 4];
		roundKey[16 * i+9] = roundKey[(i - 1) * 16 + 9] ^ roundKey[i * 16 + 5];
		roundKey[16 * i+10] = roundKey[(i - 1) * 16 + 10] ^ roundKey[i * 16 + 6];
		roundKey[16 * i+11] = roundKey[(i - 1) * 16 + 11] ^ roundKey[i * 16 + 7];
		roundKey[16 * i+12] = roundKey[(i - 1) * 16 + 12] ^ roundKey[i * 16 + 8];
		roundKey[16 * i+13] = roundKey[(i - 1) * 16 + 13] ^ roundKey[i * 16 + 9];
		roundKey[16 * i+14] = roundKey[(i - 1) * 16 + 14] ^ roundKey[i * 16 + 10];
		roundKey[16 * i+15] = roundKey[(i - 1) * 16 + 15] ^ roundKey[i * 16 + 11];
	}
}

//添加轮密钥AddRoundKey
//每个字节与轮密钥的对应字节进行异或运算
void AddRoundKey(unsigned char* state, unsigned char* roundKey) {
	for (int i = 0; i < 16; i++) {
		state[i] ^= roundKey[i];
	}
}

//对每个字节进行替换，对每个字节查表即可
void SubBytes(unsigned char* state) {
	for (int i = 0; i < 16; i++) {
		state[i] = SBox[state[i]];
	}
}

void ShiftRows(unsigned char* state) {   //   行移位
	unsigned char Tmp[16];
	Tmp[0] = state[0];	Tmp[4] = state[4];	Tmp[8] = state[8];	Tmp[12] = state[12];
	Tmp[1] = state[5];	Tmp[5] = state[9];	Tmp[9] = state[13];	Tmp[13] = state[1];
	Tmp[2] = state[10];	Tmp[6] = state[14];	Tmp[10] = state[2];	Tmp[14] = state[6];
	Tmp[3] = state[15];	Tmp[7] = state[3];	Tmp[11] = state[7];	Tmp[15] = state[11];
	for (int i = 0; i < 16; i++)
		state[i] = Tmp[i];
}


/* MixColumns 
 * 建立查找表x→2x，存储：2^−2KB，16次内存访问，实现起来比较高效
 */
 
void MixColumns(unsigned char* state) {
	unsigned char tmp[16];
	tmp[0] = (unsigned char)mul2[state[0]^ state[1]] ^ state[1] ^ state[2] ^ state[3];
	tmp[1] = (unsigned char)mul2[state[1]^ state[2]] ^state[0] ^ state[2] ^ state[3];
	tmp[2] = (unsigned char)state[0] ^ state[1] ^ mul2[state[2]^state[3]] ^ state[3];
	tmp[3] = (unsigned char)state[0] ^ state[1] ^ state[2] ^ mul2[state[3]^state[0]];

	tmp[4] = (unsigned char)mul2[state[4]^state[5]] ^ state[5] ^ state[6] ^ state[7];
	tmp[5] = (unsigned char)state[4] ^ mul2[state[5]^ state[6]] ^ state[6] ^ state[7];
	tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]^ state[7]] ^state[7];
	tmp[7] = (unsigned char)state[4] ^ state[5] ^ state[6] ^ mul2[state[7]^ state[4]];

	tmp[8] = (unsigned char)mul2[state[8]^ state[9]] ^state[9] ^ state[10] ^ state[11];
	tmp[9] = (unsigned char)state[8] ^ mul2[state[9]^ state[10]] ^ state[10] ^ state[11];
	tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]^ state[11]] ^ state[11];
	tmp[11] = (unsigned char)state[8] ^ state[9] ^ state[10] ^ mul2[state[11]^ state[8]];

	tmp[12] = (unsigned char)mul2[state[12]^ state[13]] ^ state[13] ^ state[14] ^ state[15];
	tmp[13] = (unsigned char)state[12] ^ mul2[state[13]^ state[14]] ^ state[14] ^ state[15];
	tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]^ state[15]] ^ state[15];
	tmp[15] = (unsigned char)state[12]^ state[13] ^ state[14] ^ mul2[state[15]^ state[12]];
	for (int i = 0; i < 16; i++) {
		state[i] = tmp[i];
	}
}


void AESEncrypt(unsigned char* message, unsigned char* expandedKey, unsigned char* encryptedMessage) {

	AddRoundKey(message, expandedKey); // Initial round

	for (int i = 0; i < 9; i++) {
		SubBytes(message);
		ShiftRows(message);
		MixColumns(message);
		AddRoundKey(message, expandedKey + (16 * (i + 1)));
	}

	SubBytes(message);
	ShiftRows(message);
	AddRoundKey(message, expandedKey + 160);

	for (int i = 0; i < 16; i++) {
		encryptedMessage[i] = message[i];
	}
}

int main() {
	string plaintext;
	cout << "请输入要加密的明文：\n";
	cin >> plaintext;		//输入明文
	int text_len = plaintext.length();
	if (text_len < 16)
	{
		string tmp(16 - text_len, '0');
		plaintext.append(tmp);
	}
	unsigned char paddedMessage[17];
	for (int i = 0; i < 16; i++)
	{
		paddedMessage[i] = unsigned char((plaintext[i]));
	}
	paddedMessage[16] = '\0';
	unsigned char encryptedMessage[16];
	unsigned char key[16];
	//设置明文和密钥
	//输入明文和密钥
	string tempkey;
	cout << "请输入要使用的密钥：\n";
	cin >> tempkey;		//密钥
	int key_len = tempkey.length();
	if (key_len < 16)
	{
		string tmp(16 - key_len, '0');
		tempkey.append(tmp);
	}
	cout << "输入的明文为：" << paddedMessage << endl << "输入的密钥为：" << tempkey << endl;

	for (int i = 0; i < 16; i++)
	{
		key[i] = unsigned char((tempkey[i]));
	}
	unsigned char expandedKey[176];


	LARGE_INTEGER t1, t2, tc;
	QueryPerformanceFrequency(&tc);
	QueryPerformanceCounter(&t1);


	KeyExpansion(key, expandedKey);
	AESEncrypt(paddedMessage, expandedKey, encryptedMessage);


	QueryPerformanceCounter(&t2);
	cout << "\n花费时间：" << (double)(t2.QuadPart - t1.QuadPart) / (double)tc.QuadPart << "s\n";


	cout << "加密结果为(十六进制表示)：\n";
	for (int i = 0; i < 16; i++)
	{
		printf("%x ", encryptedMessage[i]);
	}


	cout << endl;


	return 0;

}
