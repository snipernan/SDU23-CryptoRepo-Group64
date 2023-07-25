import ecdsa

# 选择一个椭圆曲线，这里以secp256k1为例
curve = ecdsa.curves.SECP256k1

# 选择一个基点G
G = curve.generator

# 选择一个随机整数d作为私钥
d = ecdsa.util.randrange(curve.order)

# 计算公钥点P
P  = d*G

# 随机选取u和v,并计算出R_
u = ecdsa.util.randrange(curve.order)
v = ecdsa.util.randrange(curve.order)
R_ = (u*G)+(v*P)

# 计算伪造的签名
inv_v = ecdsa.numbertheory.inverse_mod(v, curve.order)
r_ = (R_.x()) % curve.order
e_ = (r_*u*inv_v) % curve.order
s_ = (r_*inv_v) % curve.order
signature = (r_, s_)


# 验证伪造的签名
inv_s = ecdsa.numbertheory.inverse_mod(s_, curve.order)
R = inv_s * ((e_*G)+(r_*P))
if R == R_:
    print("验签通过")
else:
    print("验签失败")

