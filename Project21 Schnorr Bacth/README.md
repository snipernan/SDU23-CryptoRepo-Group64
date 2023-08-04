
## 简介

Schnorr Batch  是一种加速 Schnorr 签名验证的技术，它可以同时验证多个签名，从而减少验证的时间和计算成本。相比单个验证，批量验证可以在相同的计算资源下验证更多的签名。

Schnorr Batch Verification 的基本思想是将多个签名和公钥组合在一起，然后一次性进行验证。在 Schnorr 签名中，签名的验证需要计算两个值：R 和 e。因此，批量验证的关键是将多个签名中的 R 和 e 值进行组合，以便一次性计算所有签名的验证结果。

具体地，假设有 n 个签名和公钥，分别为 (pk1, m1, R1, s1), (pk2, m2, R2, s2), ..., (pkn, mn, Rn, sn)，其中 pk 是公钥，m 是消息，R 是签名中的随机值，s 是签名值。则可以将这些 R 和 e 值组成两个向量：

```
R_vec = [R1, R2, ..., Rn]
e_vec = [H(R1 || pk1 || m1), H(R2 || pk2 || m2), ..., H(Rn || pkn || mn)]
```

其中，|| 表示连接操作，H 表示哈希函数，通常使用 SHA-256。然后，可以将这两个向量作为参数传递给 Schnorr 验证函数，以一次性验证所有签名：

```
schnorr_batch_verify([pk1, pk2, ..., pkn], [m1, m2, ..., mn], R_vec, e_vec)
```

如果所有签名都有效，则返回 1；否则，返回 0。

Schnorr Batch Verification 可以显著加速 Schnorr 签名验证的过程。
## 依赖库
OpenSSL 3.1.0

## 运行结果
对300组明文私钥对进行签名

    signature = schnorr_sign(msg, x);

并分别测试了单次验证的总时间

    schnorr_verify(msg, pubkey, signature)

和采用批量验证的效率。

    schnorr_batch_verify(pk_vec, msg_vec, signature_vec)

![运行结果](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project21%20Schnorr%20Bacth/figure/aaced5eb909d314a91b8620bf2d7b4e.png)
结果上看批量验证反而稍慢一些，可能是实现时两种实现的软件实现的问题。

## 使用说明
需要在项目中包含openssl的库，如下图：
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/1.png)
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/2.png)

## 更新日志
2023.8.3 完成Schnorr Batch的实现。
2023.8.4 增加了单次Schnorr验证的实现并添加了效率测试。

## 贡献
snipernan完成此project代码编写

