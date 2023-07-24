#include <openssl/evp.h>
#include <iostream>
#include <string>

std::string sha256_length_extension_attack(const std::string& original_hash, int original_length, const std::string& new_data) {

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // Initialize hash state
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

    // Append original hash
    EVP_DigestUpdate(ctx, original_hash.c_str(), original_hash.size());

    // Set flags for automatic padding and length encoding
    EVP_MD_CTX_set_flags(ctx, 0x1 | EVP_MD_CTX_FLAG_ONESHOT);

    // Append new data
    EVP_DigestUpdate(ctx, new_data.c_str(), new_data.size());

    // Finalize hash
    EVP_DigestFinal_ex(ctx, hash, &hash_len);

    EVP_MD_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(hash), hash_len);
}

int main() {

    std::string original_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    int original_length = 0;
    std::string new_data = "test";

    std::string new_hash = sha256_length_extension_attack(original_hash, original_length, new_data);

    for (size_t i = 0; i < new_hash.size(); ++i) {
        printf("%02x", static_cast<unsigned char>(new_hash[i]));
    }
    printf("\n");

    return 0;
}
