import os
import hashlib
from ecdsa import SigningKey, VerifyingKey,util
from ecdsa.util import randrange_from_seed__trytryagain
from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod
from binascii import hexlify, unhexlify

def gen_keypair():
    privkey = randrange_from_seed__trytryagain(os.urandom(32), SECP256k1.order)
    pubkey_point = privkey * SECP256k1.generator
    pubkey_str = VerifyingKey.from_public_point(pubkey_point, curve=SECP256k1).to_string('compressed').hex()
    return privkey, pubkey_str

def sign(privkey, message):
    hash_bytes = hashlib.sha256(message.encode()).digest()
    k = SigningKey.from_secret_exponent(privkey, curve=SECP256k1, hashfunc=hashlib.sha256)
    signature_der = k.sign_deterministic(hash_bytes, hashfunc=hashlib.sha256, sigencode=util.sigencode_der)
    r, s = util.sigdecode_der(signature_der, k.curve.generator.order())
    signature = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    return signature

def verify(pubkey, message, signature):
    hash_bytes = hashlib.sha256(message.encode()).digest()
    r, s = (int(signature[:32].hex(), 16), int(signature[32:].hex(), 16))
    signature_bytes = util.sigencode_der(r, s, len(SECP256k1.order))
    vk = VerifyingKey.from_string(unhexlify(pubkey), curve=SECP256k1, hashfunc=hashlib.sha256)
    valid = vk.verify(signature_bytes, hash_bytes, sigdecode=util.sigdecode_der)
    return valid

def generate_k(z, privkey):
    while True:
        k = randrange_from_seed__trytryagain(os.urandom(32), SECP256k1.order)
        P = k * SECP256k1.generator
        r = P.x() % SECP256k1.order
        if r == 0:
            continue
        s = (inverse_mod(k, SECP256k1.order) * (z + r * privkey)) % SECP256k1.order
        if s == 0:
            continue
        break
    return k

if __name__ == "__main__":
    # 生成SM2密钥
    privkey, pubkey = gen_keypair()
    print(f"Private key: {privkey}")
    print(f"Public key: {pubkey}")

    # 对消息进行签名
    msg = "Hello, world!"
    signature = sign(privkey, msg)
    print(f"Signature: {signature.hex()}")

    # 验证签名
    valid = verify(pubkey, msg, signature)
    print(f"Valid signature: {valid}")
