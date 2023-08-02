import secrets
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import hashlib


born = 1978
now = 2021

print("------Trusted Issuer------")
seed = secrets.token_hex(16)
msg = bytes.fromhex(seed)
hash_obj = hashlib.sha256()
hash_obj.update(msg)
s = hash_obj.digest()
print("s = ", s.hex())
c = s
k = 2100 - born
for i in range(k):
    hash_obj = hashlib.sha256()
    hash_obj.update(c)
    c = hash_obj.digest()
print("c = ", c.hex())

# 加载 RSA 私钥
key = RSA.generate(2048)
# 计算数据c的 SHA256 散列值
chash_value = SHA256.new(c)
# 使用 RSA 私钥对c进行签名
signature = pkcs1_15.new(key).sign(chash_value)
# 将签名结果转换为 16 进制字符串
signature_hex = signature.hex()
print("Signature:", signature_hex)


print("------Alice's prove------")
d_0 = 2000 - born
p = s
for i in range(d_0):
    hash_obj = hashlib.sha256()
    hash_obj.update(p)
    p = hash_obj.digest()
print("p = ", p.hex())


print("------Bob's verify------")
d_1 = 2100 - 2000
c_ = p
for i in range(d_1):
    hash_obj = hashlib.sha256()
    hash_obj.update(c_)
    c_ = hash_obj.digest()
# 计算数据的 SHA256 散列值
c_hash_value = SHA256.new(c_)
try:
    pkcs1_15.new(key.public_key()).verify(c_hash_value, signature)
    print("Signature is valid.")
except (ValueError, TypeError):
    print("Signature is not valid.")
