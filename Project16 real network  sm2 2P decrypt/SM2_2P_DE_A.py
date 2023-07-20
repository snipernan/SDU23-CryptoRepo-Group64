import socket
from gmssl import sm3,func
import sm2
import struct


# 创建一个 SM2 对象
sm2_2p_A = sm2.CryptSM2(private_key=None, public_key="")


# 建立连接
print('等待建立连接……')
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8888))
server_socket.listen(1)


# 等待连接
client_socket, address = server_socket.accept()
print("连接建立成功！")


# 接收签名者发送的 T1
T1_bytes = client_socket.recv(1024)
d2_len = struct.unpack('<I', client_socket.recv(4))[0]
d2_bytes = client_socket.recv(d2_len)
d2 = int.from_bytes(d2_bytes, byteorder='big')


# 将字节串转换成原始数据
T1 = T1_bytes.decode()
T2 = sm2_2p_A.genrateT2(T1, d2)


# 发送 T2 给签名者
T2_bytes = T2.encode()
client_socket.send(T2_bytes)
print("T2发送成功")


# 关闭连接
server_socket.close()
