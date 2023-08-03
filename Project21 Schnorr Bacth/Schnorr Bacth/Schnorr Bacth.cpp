#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>


EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_secp256k1);

// 输出EC_POINT对象的坐标
void printECPointCoordinates(const EC_POINT* point) {
    // 获取EC_POINT对象的x和y坐标
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    EC_POINT_get_affine_coordinates(curve, point, x, y, NULL);

    // 将坐标转换为十六进制字符串
    char* x_hex = BN_bn2hex(x);
    char* y_hex = BN_bn2hex(y);

    // 输出坐标
    printf("x: %s\n", x_hex);
    printf("y: %s\n", y_hex);

    // 释放资源
    OPENSSL_free(x_hex);
    OPENSSL_free(y_hex);
    BN_free(x);
    BN_free(y);
}

std::vector<unsigned char> bytes_point(const EC_POINT* p) {
    const EC_GROUP* curve = EC_GROUP_new_by_curve_name(NID_secp256k1);
    BIGNUM* x = BN_new();
    BIGNUM* y = BN_new();
    if (!EC_POINT_get_affine_coordinates(curve, p, x, y, nullptr)) {
        // 处理获取坐标失败的情况
        std::cerr << "Failed to get affine coordinates" << std::endl;
        return std::vector<unsigned char>();
    }

    unsigned char prefix_byte = BN_is_odd(y) ? 0x03 : 0x02;
    std::vector<unsigned char> result;
    result.push_back(prefix_byte);

    std::string x_str = BN_bn2hex(x);
    std::string x_padded = std::string(64 - x_str.length(), '0') + x_str;

    for (size_t i = 0; i < x_padded.length(); i += 2) {
        std::string byte_str = x_padded.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
        result.push_back(byte);
    }

    BN_free(x);
    BN_free(y);
    return result;
}

std::vector<unsigned char> schnorr_sign(const std::vector<unsigned char>& msg, const BIGNUM* sk) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(curve, order, NULL);

    // 使用私钥计算公钥
    EC_POINT* pubkey = EC_POINT_new(curve);
    EC_POINT_mul(curve, pubkey, sk, NULL, NULL, ctx);

    // 将公钥转换为字节数组
    std::vector<unsigned char> pk_bytes(33);
    EC_POINT_point2oct(curve, pubkey, POINT_CONVERSION_COMPRESSED, pk_bytes.data(), pk_bytes.size(), ctx);

    // 将私钥转换为字节数组
    std::vector<unsigned char> sk_bytes(33);
    BN_bn2bin(sk, sk_bytes.data());

    // 将私钥和消息拼接起来，计算 SHA256 哈希值得到 k
    std::vector<unsigned char> data(sk_bytes.size() + msg.size());
    std::copy(sk_bytes.begin(), sk_bytes.end(), data.begin());
    std::copy(msg.begin(), msg.end(), data.begin() + sk_bytes.size());
    unsigned char k[SHA256_DIGEST_LENGTH];
    SHA256(data.data(), data.size(), k);

    // 使用 k 计算 R
    EC_POINT* G = EC_POINT_new(curve);
    const EC_POINT* generator = EC_GROUP_get0_generator(curve);
    EC_POINT_copy(G, generator);

    BIGNUM* k_bn = BN_new();
    BN_bin2bn(k, sizeof(k), k_bn);

    EC_POINT* R = EC_POINT_new(curve);
    EC_POINT_mul(curve, R, k_bn, NULL, NULL, ctx);


    // 检查 R 的 Y 坐标是否为二次剩余
    if (EC_POINT_point2oct(curve, R, POINT_CONVERSION_COMPRESSED, NULL, 0, ctx) != 33) {
        BN_sub(k_bn, order, k_bn);
        EC_POINT_mul(curve, R, k_bn, NULL, NULL, ctx);
    }


    // 计算哈希值 e
    unsigned char R_bytes[33];
    EC_POINT* G_sk = EC_POINT_new(curve);
    EC_POINT_mul(curve, G_sk, NULL, G, sk, NULL);
    std::vector<unsigned char> G_sk_vec = bytes_point(G_sk);
    size_t tmpsize = G_sk_vec.size();
    std::vector<unsigned char> e_data(33 + tmpsize + msg.size());

    EC_POINT_point2oct(curve, R, POINT_CONVERSION_COMPRESSED, R_bytes, sizeof(R_bytes), ctx);
    std::copy(R_bytes + 1, R_bytes + sizeof(R_bytes), e_data.begin());
    std::copy(G_sk_vec.begin(), G_sk_vec.end(), e_data.begin() + 32);
    std::copy(msg.begin(), msg.end(), e_data.begin() + 33 + tmpsize);

    unsigned char e[SHA256_DIGEST_LENGTH];
    SHA256(e_data.data(), e_data.size(), e);


    // 计算签名的值 s
    BIGNUM* e_bn = BN_new();
    BN_bin2bn(e, sizeof(e), e_bn);


    BIGNUM* s_bn = BN_new();
    BN_mod_mul(s_bn, sk, e_bn, order, ctx);
    BN_add(s_bn, s_bn, k_bn);
    BN_mod(s_bn, s_bn, order, ctx);

    std::vector<unsigned char> s_bytes(32);
    BN_bn2bin(s_bn, s_bytes.data());

    // 将 R 的 X 坐标和 s 拼接起来作为 Schnorr 签名的值
    std::vector<unsigned char> sig_bytes(64);
    std::copy(R_bytes + 1, R_bytes + sizeof(R_bytes), sig_bytes.begin());
    std::copy(s_bytes.begin(), s_bytes.end(), sig_bytes.begin() + 32);

    return sig_bytes;
}

bool schnorr_batch_verify(const std::vector<EC_POINT*>& pubkeys, const std::vector<std::vector<unsigned char>>& ms, const std::vector<std::vector<unsigned char>>& sigs) {
    EC_POINT* Rs = EC_POINT_new(curve);
    EC_POINT* Ps = EC_POINT_new(curve);
    BIGNUM* S = BN_new();
    BN_zero(S);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(curve, order, NULL);

    for (int i = 0; i < pubkeys.size(); i++) {
        const EC_POINT* pubkey = pubkeys[i];
        const std::vector<unsigned char>& sig = sigs[i];
        const std::vector<unsigned char>& msg = ms[i];
        BIGNUM* a = BN_new();
        //BN_set_word(a, 1);
        BN_rand(a, 256, 0, 0);

        // 将签名拆分为 r 和 s
        BIGNUM* r = BN_new();
        BIGNUM* s = BN_new();
        BN_bin2bn(sig.data(), 32, r);
        BN_bin2bn(sig.data() + 32, 32, s);

        // 计算 e
        std::vector<unsigned char> e_data(32 + 34 + msg.size());
        std::vector<unsigned char> pk_bytes(33);
        EC_POINT_point2oct(curve, pubkey, POINT_CONVERSION_COMPRESSED, pk_bytes.data(), pk_bytes.size(), ctx);

        std::copy(sig.data(), sig.data() + 32, e_data.begin());
        std::copy(pk_bytes.begin(), pk_bytes.end(), e_data.begin() + 32);
        std::copy(msg.begin(), msg.end(), e_data.begin() + 32 + 34);

        unsigned char e[SHA256_DIGEST_LENGTH];

        SHA256(e_data.data(), e_data.size(), e);


        // 计算 c 和 y
        BIGNUM* c = BN_new();

        BIGNUM* tmp1 = BN_new();
        BN_set_word(tmp1, 3);

        BIGNUM* p = BN_new();
        EC_GROUP_get_curve(curve, p, NULL, NULL, NULL);

        // 计算 r^3 mod p
        BN_mod_exp(c, r, tmp1, p, ctx);
        BN_add_word(c, 7);
        //// 将 bn 输出到标准输出流
        //char* hex_str = BN_bn2hex(c);
        //if (hex_str != nullptr) {
        //    printf("c = %s\n", hex_str);
        //    OPENSSL_free(hex_str);
        //}

        BIGNUM* y = BN_new();
        BIGNUM* exponent = BN_new();
        BIGNUM* modulus = p;

        // p + 1
        BN_add_word(modulus, 1);
        BN_copy(exponent, modulus);

        // (p + 1) // 4
        BN_rshift1(exponent, exponent);
        BN_rshift1(exponent, exponent);
        EC_GROUP_get_curve(curve, p, NULL, NULL, NULL);
        // c ^ ((p + 1) // 4)
        BN_mod_exp(y, c, exponent, p, ctx);

        // 检查 y 是否为 c 的平方根
        EC_POINT* R = EC_POINT_new(curve);
        EC_POINT_mul(curve, R, r, NULL, NULL, ctx);
        EC_POINT* point = EC_POINT_new(curve);
        EC_POINT_set_affine_coordinates(curve, point, r, y, ctx);

        if (!EC_POINT_cmp(curve, R, point, ctx)) {
            EC_POINT_set_affine_coordinates(curve, point, r, BN_dup(y), ctx);
            BN_sub(y, order, y);
        }

        if (EC_POINT_is_on_curve(curve, point, ctx) != 1) {
            std::cerr << "Error: point is not on curve" << std::endl;
            return false;
        }

        // 更新 S、Rs 和 Ps
        BIGNUM* s_a = BN_new();
        BN_mul(s_a, s, a, ctx);
        BN_add(S, S, s_a);


        EC_POINT* Ra = EC_POINT_new(curve);
        EC_POINT* tmp3 = EC_POINT_new(curve);
        EC_POINT_set_affine_coordinates(curve, tmp3, r, y, nullptr);
        EC_POINT_mul(curve, Ra, NULL, tmp3, a, ctx);
        EC_POINT_add(curve, Rs, Rs, Ra, ctx);

        BIGNUM* e_bn = BN_new();
        BN_bin2bn(e, sizeof(e), e_bn);
        BIGNUM* a_times_e = BN_new();
        EC_POINT* pubkey_a_e = EC_POINT_new(curve);
        EC_POINT* Pa = EC_POINT_new(curve);
        BN_mul(a_times_e, a, e_bn, ctx);
        EC_POINT_mul(curve, pubkey_a_e, NULL, pubkey, a_times_e, NULL);
        EC_POINT_add(curve, Ps, Ps, pubkey_a_e, nullptr);
        // 释放资源
        BN_free(r);
        BN_free(s);
        BN_free(c);
        BN_free(y);
        BN_free(e_bn);
        EC_POINT_free(R);
        EC_POINT_free(point);
        EC_POINT_free(Ra);
        EC_POINT_free(Pa);
    }

    // 验证签名
    EC_POINT* G = EC_POINT_new(curve);
    const EC_POINT* generator = EC_GROUP_get0_generator(curve);
    EC_POINT_copy(G, generator);

    EC_POINT* LHS = EC_POINT_new(curve);
    EC_POINT_mul(curve, LHS, NULL, G, S, ctx);

    EC_POINT* RHS = EC_POINT_new(curve);
    EC_POINT_add(curve, RHS, Rs, Ps, ctx);

    bool result = (EC_POINT_cmp(curve, LHS, RHS, ctx) == 0);


    // 释放资源
    EC_POINT_free(Rs);
    EC_POINT_free(Ps);
    BN_free(S);
    EC_POINT_free(G);
    EC_POINT_free(LHS);
    EC_POINT_free(RHS);

    return result;
}

int main() {
	EC_POINT* G = EC_POINT_new(curve);
	const EC_POINT* generator = EC_GROUP_get0_generator(curve);
	EC_POINT_copy(G, generator);

	BIGNUM* x = BN_new();
	BIGNUM* y = BN_new();
	EC_POINT_get_affine_coordinates(curve, G, x, y, NULL);

	EC_POINT* pubkey = EC_POINT_new(curve);
	EC_POINT_mul(curve, pubkey, x, NULL, NULL, NULL);

    std::vector<unsigned char> msg(31, 0);

    std::vector<unsigned char> signature(64);
    signature = schnorr_sign(msg, x);

    // 将 signature 添加到 std::vector 中
    std::vector<std::vector<unsigned char>> signature_vec;
    signature_vec.push_back(signature);

    // 将 pk 添加到 std::vector 中
    std::vector<EC_POINT*> pk_vec;
    pk_vec.push_back(pubkey);

    // 将 msg 添加到 std::vector 中
    std::vector<std::vector<unsigned char>> msg_vec;
    msg_vec.push_back(msg);
   
    if (schnorr_batch_verify(pk_vec, msg_vec, signature_vec) == 1) {
        std::cout << "验证通过";
    };

}
	
