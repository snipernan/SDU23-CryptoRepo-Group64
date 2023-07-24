import socket
from gmssl import sm3, func
import sm2
import struct


# 创建一个 SM2 对象
sm2_crypt = sm2.CryptSM2(private_key=None, public_key="")


# 建立连接
print('等待建立连接……')
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 8888))
print("连接建立成功！")
print("等待签名……")


# 生成随机数 P1 并发送给验证者,为防止粘包，先发送了数据长度再发送数据
P1 = sm2_crypt.genrateP1()
P1_bytes = P1.encode()
length = len(P1_bytes)
length_bytes = length.to_bytes(4, byteorder='big')
client_socket.send(length_bytes)
client_socket.send(P1_bytes)


# 接收验证者发送的 P，并根据 P 生成公钥和私钥
P_bytes = client_socket.recv(1024)
P = P_bytes.decode()


# 生成待签名数据 Z 和 M
Z = b'Padding'
M = b'Massage'


# 计算 e 和 Q1，并将其发送给验证者
e = sm2_crypt.get_e(Z, M)
e_bytes = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
length = len(e_bytes)
Q1 = sm2_crypt.get_Q1()
Q1_bytes = Q1.encode()
client_socket.send(Q1_bytes)
client_socket.sendall(struct.pack('<I', length) + e_bytes)


# 接收验证者发送的 r、s2 和 s3，并根据其计算出签名值 sig
r_len = struct.unpack('<I', client_socket.recv(4))[0]
r_bytes = client_socket.recv(r_len)
r = int.from_bytes(r_bytes, byteorder='big')
s2_len = struct.unpack('<I', client_socket.recv(4))[0]
s2_bytes = client_socket.recv(s2_len)
s2 = int.from_bytes(s2_bytes, byteorder='big')
s3_len = struct.unpack('<I', client_socket.recv(4))[0]
s3_bytes = client_socket.recv(s3_len)
s3 = int.from_bytes(s3_bytes, byteorder='big')
sig = sm2_crypt.sign_2P_last(r, s2, s3)
print("签名完成！")


# 将签名值发送给验证者
sig_bytes = sig.encode()
client_socket.send(sig_bytes)
d1 = sm2_crypt.d1
d1_bytes = d1.to_bytes((d1.bit_length() + 7) // 8, byteorder='big')
d1_length = len(d1_bytes)
client_socket.sendall(struct.pack('<I', d1_length) + d1_bytes)


# 关闭连接
client_socket.close()
