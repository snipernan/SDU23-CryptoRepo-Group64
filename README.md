
# [SDU23-CryptoRepo](https://github.com/snipernan/SDU23-CryptoRepo)

2023  创新创业实践课实践项目小组repository

**队伍成员(首字母排序):**

- 王苏楠[@[snipernan](https://github.com/snipernan)]
- 张嘉树   [@[JarmanZ](https://github.com/JarmanZ)]

**人员分工表：**

|姓名|学号| 负责project |
|--|--|--|
| 王苏楠 | 202100460027 |Project 1、2、3、4、20、21
|张嘉树|202100460057|Project 5、6、9、11、14、15、16、18、19


## 项目列表
| Project 编号 | 项目名 |实现方式|实现效果
|--|--|--|--|
| 1 | [implement the naïve birthday attack of reduced SM3](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3) |  - 使用查找表了实现生日攻击。<br>- 使用了openSSL的sm3和openMP的多线程。| 完成了48bit的碰撞搜索|
| 2 | [implement the Rho method of reduced SM3](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project2%20implement%20the%20Rho%20method%20of%20reduced%20SM3) |  - 使用Rho方法实现生日攻击。<br>- 使用了openSSL的sm3和openMP的多线程。| 完成了32bit的碰撞搜索|
| 3 | [implement length extension attack for SM3, SHA256, etc.](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project3%20implement%20length%20extension%20attack) |  - 可以自定义输入一个哈希值和要拓展的消息输出级联后的哈希值 | 完成了长度拓展攻击的实现|
| 4 | [do your best to optimize SM3 implementation (software)](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project4%20do%20your%20best%20to%20optimize%20SM3%20implementation%20%28software%29) |  - 使用O2优化的内联函数，循环展开，指令重排<br>-比openssl的实现快一倍<br>-完成了simd版本的实现| 1000轮512bit-加密用时600ms|
| 5 | [Impl Merkle Tree following RFC6962](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project5%20Impl%20Merkle%20Tree%20following%20RFC6962) |  - 生成证明路径时，使用二进制表示法表示叶子节点的位置，大大降低证明路径的长度<br>-证明路径中只存储了相对位置和哈希值，保护数据的隐私性| 完成了RFC6962结构的Merkle Tree实现|
| 6 | [impl this protocol with actual network communication](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project6%20impl%20this%20protocol%20with%20actual%20network%20communication) |  -采用 PKCS#1 v1.5 签名算法来对证书进行签名<br>-在证书撤销过程中，重新生成了签名方的私钥，有效防止证书被滥用。| 成功通过哈希函数进行范围证明|
| 9 | [AES / SM4 software implementation](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project9%20AES%20%20SM4%20software%20implementation) |  -实现了AES128和SM4<br>-建立查找表x→2x，存储：2^−2KB，16次内存访问|AES单条数据加密用时3微秒|
| 11 | [impl sm2 with RFC6979](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project11%20impl%20sm2%20with%20RFC6979) |  -使用 RFC 6979 算法实现sm2签名|使用 `sign()` 函数对消息进行签名，并通过 `verify()` 函数验证签名的有效性。|
| 14 | [Implement a PGP scheme with SM2](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project14%20Implement%20a%20PGP%20scheme%20with%20SM2) |  -通过SM2实现PGP加解密实例<br>-使用公钥密码学和对称密码学相结合的方式保护了数据的机密性和完整性|使用国密公钥密码标准sm2和对称密码sm4完成了PGP的实现|
| 15 | [implement sm2 2P sign with real network communication](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project15%20real%20network%20%20sm2%202P%20sig) |  -为防止粘包，先发送了数据长度再发送数据<br>-通信使用了 TCP 连接，实现了数据的可靠传输和通信的稳定性|实现了现实网络环境中的SM2签名|
| 16 | [implement sm2 2P decrypt with real network communication](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project16%20real%20network%20%20sm2%202P%20decrypt) |  -实现过程和project15类似，签名换为加解密<br>-通信使用了 TCP 连接，实现了数据的可靠传输和通信的稳定性|在真实通信网络上实现了SM2_2P解密|
| 18 | [send a tx on Bitcoin testnet, and parse the tx data down to every bit, better write script yourself](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project18%20send%20and%20parse%20tx%20on%20Bitcoin%20testnet) |  -定义的交易ID：`5a7536f5d6d19d45974a05e6baab696df0db9ee4abd1b87696a6f1f31c0d5a4b`|成功在`https://blockstream.info/`上发起了一笔交易并且追踪了交易信息。|
| 19 | [forge a signature to pretend that you are Satoshi](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project19%20forge%20a%20signature%20to%20pretend%20that%20you%20are%20SatoshiPretend%20Satoshiforge_sig.py) |  -基于存在性伪造攻击对ECDSA签名进行存在性伪造，伪装成了Satoshi的身份|成功伪造并通过了验证|
| 20 | [ECMH PoC](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project20%20ECMH%20PoC) |  -实现基于 ECMH 算法的哈希函数，可以进行多重集的计算对<br>-测试使用了`{a}` 和 `{a, a}` 两个多重集进行哈希，并输出其哈希值|成功实现了ECMH PoC|
| 21 | [Schnorr Bacth](https://github.com/snipernan/SDU23-CryptoRepo/tree/main/Project21%20Schnorr%20Bacth) |  -实现批量的Schnorr 签名验证<br>-代码中包装了雅可比符号的计算<br>`int jacobi(const BIGNUM* a, const BIGNUM* n, BN_CTX* ctx)`<br>-单个签名的验证也进行了实现<br>`schnorr_sign(const std::vector<unsigned char>& msg, const BIGNUM* sk)`<br>-应该是首个开源C++实现的Schnorr Bacth|300条签名批量验证用时460ms|
