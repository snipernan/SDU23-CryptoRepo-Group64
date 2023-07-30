import gmssl
from gmssl import sm2
from gmssl import sm4
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 定义 SM2 椭圆曲线参数
params = ec.SECP256K1()

# 生成 SM2 密钥对
sm2_private_key = ec.generate_private_key(params, default_backend())
sm2_public_key = sm2_private_key.public_key()

# 将密钥转换为字节类型数据
private_key_bytes = sm2_private_key.private_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_bytes = sm2_public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


# 将 bytes 格式的私钥和公钥转换为 hex 格式的字符串
private_key_hex = private_key_bytes.hex()
public_key_hex = public_key_bytes.hex()


# 生成 SM2 密钥对
sm2_crypt = gmssl.sm2.CryptSM2(public_key=public_key_hex, private_key=private_key_hex)

# 生成 SM4 密钥
sm4_key = os.urandom(16)
sm4_encrypt = gmssl.sm4.CryptSM4()
sm4_encrypt.set_key(sm4_key, mode= 0)

# 加密明文
print("----------------加密明文----------------")
plaintext = b'This is test'
ciphertext = sm4_key + sm4_encrypt.crypt_ecb( plaintext)
print(f'待加密明文为：{plaintext}')
print(f"使用的sm4密钥为：{sm4_key.hex()}")

# 使用 SM2 加密 SM4 密钥
print("----------------加密密钥----------------")
encrypted_key = sm2_crypt.encrypt(sm4_key)
print(f"使用sm2加密后的sm4密钥为：{encrypted_key.hex()}")

# 使用 SM2 解密 SM4 密钥
print("----------------解密密钥----------------")
decrypted_key = sm2_crypt.decrypt(encrypted_key)
print(f"解密后的sm4密钥为：{sm4_key.hex()}")

# 解密密文
print("----------------解密密文----------------")
sm4_decrypt = gmssl.sm4.CryptSM4()
sm4_decrypt.set_key(sm4_key, mode= 1)
decrypted_plaintext = sm4_decrypt.crypt_ecb(ciphertext[16:])
print("解密结果为：")
print(decrypted_plaintext.decode('utf-8'))
