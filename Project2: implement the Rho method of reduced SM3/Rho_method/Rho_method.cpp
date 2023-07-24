#include <iostream>
#include <cstring>
#include <cstdlib>
#include <openssl/evp.h>
#include <chrono>

// 定义 碰撞长度长度
#define COLLISION_LEN 4

// 定义 SM3 哈希值长度
#define SM3_DIGEST_LENGTH 32

// 定义哈希值结构体
struct item {
    unsigned char dgst[SM3_DIGEST_LENGTH];
};

// 计算哈希值
void sm3(const unsigned char* msg, size_t msglen, unsigned char dgst[SM3_DIGEST_LENGTH]) {
    uint32_t out_size = SM3_DIGEST_LENGTH;
    EVP_Digest(msg, msglen, dgst, &out_size, EVP_sm3(), nullptr);
}

int main(int argc, char** argv) {
    // 生成随机消息
    const int msg_len = 32; // 消息长度
    char msg[msg_len + 1]; // 用于存储消息的字符数组
    for (int i = 0; i < msg_len; i++) {
        msg[i] = rand() % 26 + 'a'; // 生成随机小写字母
    }
    msg[msg_len] = '\0'; // 添加字符串结尾符号

    // 生成第二个随机消息
    char msg2[msg_len + 1];
    for (int i = 0; i < msg_len; i++) {
        msg2[i] = rand() % 26 + 'a'; // 生成随机小写字母
    }
    msg2[msg_len] = '\0'; // 添加字符串结尾符号

    // 定义参数
    const size_t rho_length = 4;
    const size_t cmp_len = COLLISION_LEN;

    std::cout << std::endl << "-------------进行 " << COLLISION_LEN * 8 << "bit 碰撞搜索-------------- " << std::endl << std::endl;

    // 计算初始哈希值
    item* rho = new item[rho_length];
    sm3(reinterpret_cast<const unsigned char*>(msg), strlen(msg), rho[0].dgst);

    // 循环查找哈希碰撞
    int i = 0;
    auto start_time = std::chrono::high_resolution_clock::now();
    while (memcmp(rho[0].dgst, rho[1].dgst, cmp_len) != 0) {
        sm3(rho[i].dgst, SM3_DIGEST_LENGTH, rho[(i + 1) % rho_length].dgst);
        i = (i + 1) % rho_length;
    }
    auto end_time = std::chrono::high_resolution_clock::now();

    // 输出结果
    std::cout << "Found hash collision:" << std::endl;
    std::cout << "Message 1: " << msg << std::endl;
    std::cout << "Hash 1: ";
    for (int j = 0; j < SM3_DIGEST_LENGTH; ++j) {
        printf("%02x", rho[0].dgst[j]);
    }
    std::cout << std::endl;
    std::cout << "Message 2: " << msg2 << std::endl;
    std::cout << "Hash 2: ";
    for (int j = 0; j < SM3_DIGEST_LENGTH; ++j) {
        printf("%02x", rho[1].dgst[j]);
    }
    std::cout << std::endl;

    // 释放内存
    delete[] rho;

    // 输出结果
    std::cout << "用时: " << std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count() << " ms" << std::endl;

    return 0;
}
