## 简介
通过伪造签名来伪装你是Satoshi


## 项目说明
对于ECDSA签名，有存在性伪造可以对签名进行伪造进而伪装攻击者的身份，下面我们将给出一个伪造ECDSA签名的实现。

![19](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/e615fe65-8a30-4fe4-9cbc-64f51147bcea)

首先我们生成一个原始的签名，有私钥d和公钥P，接下来我们将伪造一个签名。

第一步是选取随机数u和v，并依据这两个随机数计算出R'。

接下来就要通过此进行签名的伪造：

`inv_v = ecdsa.numbertheory.inverse_mod(v, curve.order)`

`r_ = (R_.x()) % curve.order`

`e_ = (r_*u*inv_v) % curve.order`

`s_ = (r_*inv_v) % curve.order`

`signature = (r_, s_)`

由此我们得到了一个伪造的签名，即对e_的签名σ=(r_,s_)。最后我们还需要对这个伪造的签名进行验签，检验是否可以通过验证。验签过程只需参考上图中公式即可。

## 运行结果
签名验证通过，身份伪造成功！

![项目19](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/9f6c80e0-6822-4795-ad26-420a81efb1f1)


## 更新日志
2023.7.24 完成Satoshi身份伪造Python代码

## 贡献
张嘉树完成此project代码编写
