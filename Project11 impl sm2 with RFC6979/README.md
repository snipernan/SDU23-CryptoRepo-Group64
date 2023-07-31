## 简介
使用 RFC 6979 算法实现sm2签名。
## 依赖库
ecdsa 0.18.0


## 项目说明
RFC 6979 算法是一种使用伪随机数生成器生成确定性签名的算法，它可以解决传统的基于随机数生成器的签名算法中存在的随机数重复和预测问题。在这个本项目的代码中，使用了 sign_deterministic() 方法来生成确定性签名，该方法会使用 hashlib.sha256() 哈希函数和 RFC 6979 算法生成一个伪随机数，然后使用该伪随机数生成签名。
具体来说实现方式如下：

>gen_keypair() 函数，该函数使用 randrange_from_seed__trytryagain() 方法生成一个随机的私钥，并使用 VerifyingKey.from_public_point() 方法从公钥点中获取公钥字符串，最后将私钥和公钥字符串作为元组返回。

>sign() 函数，该函数接受一个私钥和一个消息作为输入，使用 hashlib.sha256() 哈希函数计算消息的哈希值，然后使用 SigningKey.from_secret_exponent() 方法从私钥中创建签名密钥对象，并使用 sign_deterministic() 方法生成一个确定性签名，最后使用 util.sigdecode_der() 方法将签名元组解码为字节串对象，并将其拼接为一个 64 字节的字节串，作为签名结果返回。

>verify() 函数，该函数接受一个公钥、一个消息和一个签名作为输入，使用 hashlib.sha256() 哈希函数计算消息的哈希值，然后使用 util.sigencode_der() 方法将签名元组编码为 DER 编码格式的字节串对象，并使用 VerifyingKey.from_string() 方法从公钥字符串中创建验证密钥对象，并使用 verify() 方法验证签名的有效性，最后返回验证结果的布尔值。

>generate_k() 函数，该函数接受一个消息的哈希值和一个私钥作为输入，使用 randrange_from_seed__trytryagain() 方法生成一个伪随机数 k，使用 SM2 算法中的计算公式计算 r 和 s 值，最后返回生成的随机数 k。

gen_keypair() 函数生成一个 SM2 密钥对，然后使用 sign() 函数对消息进行签名，最后使用 verify() 函数验证签名的有效性，并输出签名验证结果。
## 运行结果
输出结果显示，签名成功通过验证：

![项目14](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/01e9e08d-4c82-4ba3-9b9c-a28b0fadc1ae)


## 更新日志
2023.7.31日完成sm2.py的编写和调试

## 贡献
张嘉树完成此project代码编写
