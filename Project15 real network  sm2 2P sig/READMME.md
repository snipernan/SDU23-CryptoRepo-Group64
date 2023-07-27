## 简介
实现SM2_2P_SIG签名
## 依赖库
OpenSSL 3.1.0


## 过程介绍
![15](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/d15c4f3d-4caf-4a6a-a51b-1cc4a3ab28c2)

-Alice与Bob分别随机选取私有子密钥

-Alice通过子密钥和基点G计算P1并将其发送给Bob

-Bob利用P1和私有子密钥计算公钥P

-Alice对明文M进行处理得到e并选取一个随机数与基点G相乘得到Q1，将Q1和e一并发送给Bob

-Bob通过e和Q1计算出签名中的r，并计算出s2和s3，将这三个数据发送给Alice

-Alice通过r、s2和s3计算出签名σ=(r,s)

## 运行结果
![项目15](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/ce82294e-2250-44e4-bb13-90fd5d72b3f9)


## 更新日志
2023.7.11 完成sm2_2p_sig的python代码
## 贡献
张嘉树完成此project代码编写
