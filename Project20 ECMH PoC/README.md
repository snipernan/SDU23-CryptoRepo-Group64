
## 简介
使用secp256k1曲线和SHA-256哈希函数计算多元素集合的ECMH。

`ecmh_hash`函数计算包含相同元素"a"的两个多重集合的ECMH。程序以十六进制格式输出结果的摘要
## 依赖库
OpenSSL 3.1.0

## 运行结果
![运行结果](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project20%20ECMH%20PoC/figure/20fcb0bf60919db1188fcd1532a5bc3.png)

## 使用说明
需要在项目中包含openssl的库，如下图：
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/1.png)
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/2.png)

## 更新日志
2023.7.27 完成ECMH的实现。

## 贡献
snipernan完成此project代码编写

