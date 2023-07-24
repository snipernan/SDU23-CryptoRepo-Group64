#include <iostream>
#include <cstring>
#include <map>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <omp.h>
#include <chrono>

#define num_threads 16

using namespace std;
using namespace chrono;

const int COLLISION_LEN = 48;
const int STORE_LEN = ((COLLISION_LEN + 7) / 8);
const int TABLE_SIZE = 1 << (COLLISION_LEN / 2);

// Construct the collision table
void build_collision_table(uint8_t* rand_in, map<string, uint64_t>& collision_table) {
    // Construct the SM3 context
    EVP_MD_CTX* mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
    uint8_t first_value[32];
    memcpy(first_value, rand_in, 32);
    uint64_t offset = 0;

    // Calculate the offsets and insert into the collision table
    for (int i = 0; i < TABLE_SIZE; i++) {

        EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
        EVP_DigestUpdate(mdctx, first_value, 32);

        // Calculate the hash value and extract the first STORE_LEN bytes as the key
        uint8_t hash_value[32];
        //unsigned int hash_len;
        EVP_DigestFinal_ex(mdctx, hash_value, NULL);


        string key((char*)hash_value, (char*)(hash_value + STORE_LEN));


        collision_table[key] = offset;


        // Increment the random input by 1
        for (int j = 0; j < 8; j++) {
            first_value[31 - j] += 1;
            if (first_value[31 - j] != 0) {
                break;
            }
        }

        // Increment the offset by 1
        offset += 1;
    }

    // Free the SM3 context
    EVP_MD_CTX_free(mdctx);
}

// Find the collision using single thread
void find_collision_birthday(uint8_t* rand_in, uint64_t* offsets, map<string, uint64_t>& collision_table) {
    // Construct the SM3 context
    EVP_MD_CTX* mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);

    // Generate a random input
    uint8_t collision[32];
    RAND_bytes(collision, 32);

    // Find the collision
    string key, hash_str;
    uint64_t offset;
    int cnt = 0;
    double t1 = omp_get_wtime();
    double t2;
    while (true) {
        cnt++;

        // Update the SM3 context with the collision
        EVP_DigestUpdate(mdctx, collision, 32);

        // Calculate the hash value and extract the first STORE_LEN bytes as the key
        uint8_t hash_value[32];
        unsigned int hash_len;
        EVP_DigestFinal_ex(mdctx, hash_value, &hash_len);
        key = string((char*)hash_value, (char*)(hash_value + STORE_LEN));

        // Look up the key in the collision table
        auto it = collision_table.find(key);
        if (it != collision_table.end()) {
            offset = it->second;

            // Calculate the final hash value
            uint8_t final_value[32];
            uint8_t pre_hash_value[32];
            memcpy(final_value, rand_in, 32);
            for (uint64_t p = 0; p < offset ; p++) {
                bool should_break = false;
                for (int j = 0; j < 8 && !should_break; j++) {
                    final_value[31 - j] += 1;
                    if (final_value[31 - j] != 0) {
                        should_break = true;
                    }
                }
            }
            EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
            EVP_DigestUpdate(mdctx, final_value, 32);
            EVP_DigestFinal_ex(mdctx, pre_hash_value, NULL);

            // Print the result
            cout << "Input: ";
            for (int i = 0; i < 32; i++) {
                cout << hex << setw(2) << setfill('0') << (int)final_value[i];
            }
            cout << endl;

            cout << "Hash(input): ";
            for (int i = 0; i < EVP_MD_size(EVP_sm3()); i++) {
                cout << hex << setw(2) << setfill('0') << (int)pre_hash_value[i];
            }
            cout << endl;

            cout << "Collision: ";
            for (int i = 0; i < 32; i++) {
                cout << hex << setw(2) << setfill('0') << (int)collision[i];
            }
            cout << endl;

            cout << "Hash(Collision): ";
            for (int i = 0; i < 32; i++) {
                cout << hex << setw(2) << setfill('0') << (int)hash_value[i];
            }
            cout << endl;
            break;
        }

        // Increment the collision by 1
        for (int i = 0; i < 8; i++) {
            collision[31 - i] += 1;
            if (collision[31 - i] != 0) {
                break;
            }
        }
    }

    cout << "Collision found after " << dec << cnt << " iterations." << endl;

    // Free the SM3 context
    EVP_MD_CTX_free(mdctx);
}

// Find the collision using multiple threads
void find_collision_multi(uint8_t* rand_in, map<string, uint64_t>& collision_table) {
    // Construct the SM3 context
    EVP_MD_CTX* mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);

    // Initialize the collision vector
    uint8_t collisions[num_threads][32];
    for (int i = 0; i < num_threads; i++) {
        RAND_bytes(collisions[i], 32);
    }

    // Find the collision
    string key, hash_str;
    uint64_t offset=0;
    int cnt = 0;

#pragma omp parallel for num_threads(num_threads) shared(collisions, key, offset, hash_str, cnt)
    for (int i = 0; i < num_threads; i++) {
        // Construct the SM3 context
        EVP_MD_CTX* mdctx;
        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);

        // Find the collision for this thread
        while (true) {
            cnt++;

            // Update the SM3 context with the collision
            EVP_DigestUpdate(mdctx, collisions[i], 32);

            // Calculate the hash value and extract the first STORE_LEN bytes as the key
            uint8_t hash_value[32];
            EVP_DigestFinal_ex(mdctx, hash_value, NULL);
            key = string((char*)hash_value, (char*)(hash_value + STORE_LEN));

            // Look up the key in the collision table
            auto it = collision_table.find(key);
            if (it != collision_table.end()) {
                offset = it->second;

                // Calculate the final hash value
                uint8_t final_value[32];
                uint8_t pre_hash_value[32];
                memcpy(final_value, rand_in, 32);
                for (uint64_t p = 0; p < offset; p++) {
                    bool should_break = false;
                    for (int j = 0; j < 8 && !should_break; j++) {
                        final_value[31 - j] += 1;
                        if (final_value[31 - j] != 0) {
                            should_break = true;
                        }
                    }
                }
                EVP_DigestInit_ex(mdctx, EVP_sm3(), NULL);
                EVP_DigestUpdate(mdctx, final_value, 32);
                EVP_DigestFinal_ex(mdctx, pre_hash_value, NULL);

                // Print the result
                cout << "Input: ";
                for (int i = 0; i < 32; i++) {
                    cout << hex << setw(2) << setfill('0') << (int)final_value[i];
                }
                cout << endl;

                cout << "Hash(input): ";
                for (int i = 0; i < EVP_MD_size(EVP_sm3()); i++) {
                    cout << hex << setw(2) << setfill('0') << (int)pre_hash_value[i];
                }
                cout << endl;

                cout << "Collision: ";
                for (int j = 0; j < 32; j++) {
                    cout << hex << setw(2) << setfill('0') << (int)collisions[i][j];
                }
                cout << endl;

                cout << "Hash(Collision): ";
                for (int i = 0; i < 32; i++) {
                    cout << hex << setw(2) << setfill('0') << (int)hash_value[i];
                }
                cout << endl;

                cout << "Collision found after " <<dec<<cnt << " iterations." << endl;
                return;
            }

            // Increment the collision by 1
            for (int j = 0; j < 8; j++) {
                collisions[i][31 - j] += 1;
                if (collisions[i][31 - j] != 0) {
                    break;
                }
            }
        }

        // Free the SM3 context
        EVP_MD_CTX_free(mdctx);
    }

    // Free the SM3 context
    EVP_MD_CTX_free(mdctx);
}

int main() {
    cout << endl << "-------------进行 "<< COLLISION_LEN<<"bit 碰撞搜索-------------- " << endl << endl;
    // Initialize the random input and offsets
    uint8_t rand_in[32];
    static uint64_t offsets[TABLE_SIZE];
    RAND_bytes(rand_in, 32);
    // Build the collision table
    static map<string, uint64_t> collision_table;
    cout << endl << "-----------------创建查找表------------------- " << endl << endl;
    auto start_time1 = high_resolution_clock::now();
    build_collision_table(rand_in, collision_table);
    auto end_time1 = high_resolution_clock::now();
    auto duration1 = duration_cast<milliseconds>(end_time1 - start_time1);
    cout << "查找表创建用时: " << duration1.count() << " ms" << endl;

    // Find the collision using a single thread
    cout << endl << "--------------------单线程生日攻击-------------------- " << endl << endl;
    auto start_time2 = high_resolution_clock::now();
    find_collision_birthday(rand_in, offsets, collision_table);
    auto end_time2 = high_resolution_clock::now();
    auto duration2 = duration_cast<milliseconds>(end_time2 - start_time2);
    cout << "单线程攻击用时: " << duration2.count() << " ms" << endl;

    // Find the collision using multiple threads
    cout << endl << "--------------------16线程生日攻击-------------------- " << endl << endl;
    auto start_time3 = high_resolution_clock::now();
    find_collision_multi(rand_in, collision_table);
    auto end_time3 = high_resolution_clock::now();
    auto duration3 = duration_cast<milliseconds>(end_time3 - start_time3);
    cout << "16线程攻击用时: " << duration3.count() << " ms" << endl;
    return 0;
}

