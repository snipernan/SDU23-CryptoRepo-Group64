## 简介
在真实通信网络上实现SM2_2P解密
## 依赖库
gmssl


## 过程介绍
![16](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/2d6f5b54-c6ba-4f28-a1ac-5e4d9389399a)

-产生子密钥：Alice和Bob分别随机生成一个私有子密钥

-处理密文：Alice对密文进行处理并产生T1，再将T1发送给Bob

-计算T2：Bob拿到T1后，通过自己的私有子密钥和T1计算生成T2并将其发送给Alice

-恢复明文M：Alice根据T2，解密并恢复明文

## 运行结果
![项目16](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/3d64d169-f18a-4893-94d5-daa23a1fe3c8)

## 更新日志
2023.7.11 完成sm2_2p_decrypt的python代码

## 贡献
张嘉树完成此project代码编写
