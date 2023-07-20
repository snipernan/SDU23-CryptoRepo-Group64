import socket
import sm2
import struct


# 创建一个 SM2 对象
sm2_2p_B = sm2.CryptSM2(private_key=None, public_key="")


# 待加密的明文
M = 'THIS IS A TEST'
data = M.encode()


# 建立连接
print('等待建立连接……')
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 8888))
print("连接建立成功！")
print("等待加密……")


# 进行加密
P1, d1 = sm2_2p_B.genrateP1()
P, d2 = sm2_2p_B.genrateP(P1)
a = (d1 * d2) % int(sm2_2p_B.ecc_table['n'], base=16)
privatekey = str(hex(sm2_2p_B.inverse_mod_prime(a, int(sm2_2p_B.ecc_table['n'], base=16)) - 1))
sm2_2p_B.set_key(publickey=P, privatekey=privatekey)
C, C1 = sm2_2p_B.encrypt(data)
print("加密成功！")


# 生成随机数 T1 并发送给合作者
T1 = sm2_2p_B.genrateT1(C1)
T1_bytes = T1.encode()
d2_bytes = sm2_2p_B.d2.to_bytes((sm2_2p_B.d2.bit_length() + 7) // 8, byteorder='big')
length = len(d2_bytes)
client_socket.send(T1_bytes)
client_socket.sendall(struct.pack('<I', length) + d2_bytes)


# 接收验证者发送的 T2，并根据 T2 进行解密
print("开始解密……")
T2_bytes = client_socket.recv(1024)
T2 = T2_bytes.decode()
_M = sm2_2p_B.decrypt(C, T2)
if _M is not None:
    print(f'解密成功!\n解密结果为：{_M.decode()}')


# 关闭连接
client_socket.close()
