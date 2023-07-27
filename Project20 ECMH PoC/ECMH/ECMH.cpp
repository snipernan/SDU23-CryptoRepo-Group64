#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Hash function to compute the hash of a message
void hash(unsigned char* msg, size_t len, unsigned char* digest) {
    // Use SHA256 as the hash function
    EVP_MD_CTX* mdctx;
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, msg, len);
    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);
}

// Map an element to an EC point
EC_POINT* map_to_point(unsigned char* elem, size_t len, EC_GROUP* group) {
    // Compute the hash of the element
    unsigned char digest[SHA256_DIGEST_LENGTH];
    hash(elem, len, digest);
    // Use the hash value to generate an EC point
    BIGNUM* bn_x, * bn_y;
    bn_x = BN_new();
    bn_y = BN_new();
    BN_bin2bn(digest, SHA256_DIGEST_LENGTH / 2, bn_x);
    BN_bin2bn(digest + SHA256_DIGEST_LENGTH / 2, SHA256_DIGEST_LENGTH / 2, bn_y);
    EC_POINT* point;
    point = EC_POINT_new(group);
    EC_POINT_set_affine_coordinates(group, point, bn_x, bn_y, NULL);
    BN_free(bn_x);
    BN_free(bn_y);
    return point;
}

// Compute the ECMH hash of a multiset
void ecmh_hash(unsigned char** elems, size_t* lens, int count, unsigned char* digest) {
    // Use the secp256k1 curve
    EC_GROUP* group;
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    // Initialize the resulting point to the infinity point
    EC_POINT* result;
    result = EC_POINT_new(group);
    // Map each element to an EC point and add it to the resulting point
    for (int i = 0; i < count; i++) {
        EC_POINT* point;
        point = map_to_point(elems[i], lens[i], group);
        EC_POINT_add(group, result, result, point, NULL);
        EC_POINT_free(point);
    }
    // Convert the resulting point to a byte array
    unsigned char* buf;
    int len;
    len = EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED, NULL, 0, NULL);
    buf = (unsigned char*)malloc(len);
    EC_POINT_point2oct(group, result, POINT_CONVERSION_COMPRESSED, buf, len, NULL);
    // Compute the hash of the byte array to get the final digest
    hash(buf, len, digest);
    // Clean up
    free(buf);
    EC_POINT_free(result);
    EC_GROUP_free(group);
}

int main() {
    // Example usage: compute the ECMH hash of {a} and {a, a}
    unsigned char* elems[2];
    size_t lens[2];
    elems[0] = (unsigned char*)"a";
    elems[1] = (unsigned char*)"a";
    lens[0] = strlen((char*)elems[0]);
    lens[1] = strlen((char*)elems[1]);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    ecmh_hash(elems, lens, 1, digest);
    printf("hash({a}) = ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    ecmh_hash(elems, lens, 2, digest);
    printf("hash({a,a}) = ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    return 0;
}
