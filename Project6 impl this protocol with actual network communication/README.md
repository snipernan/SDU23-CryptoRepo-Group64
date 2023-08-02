## 简介
通过哈希函数进行范围证明。
## 依赖库
pycryptodome 3.18.0
gmssl 3.2.2


## 项目说明
本项目是关于使用哈希函数进行范围证明，是一种加密技术，用于证明一个秘密值位于特定的范围内，而不会透露实际值。

在本项目中即Alice想向Bob证明她的年龄大于21岁且不透露真实值。具体流程如下图所示：

![6](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/36396a1a-e12d-4a9f-a480-146faeb793b6)

可以看到整体步骤分为三部分，首先是一个可信的第三方为A随机选取和计算一个哈希值s，并给出对c的签名sigc。

之后Alice想Bob进行证明，她要做的是计算出p并将p连同sigc一并发送给Bob。

最后由Bob借助p计算出c'并验证对c'的签名等于sigc，这样就通过了对Alice的验证。

## 运行结果
下面是程序的运行结果，可以看出最终签名通过，Bob可以在Alice不泄露具体年龄信息的情况下确定Alice至少年满21岁：
![项目6](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/5fe12cd2-b876-454f-9d60-14f8170fb9ba)

## 更新日志
2023.7.20 完成range_prove.py的编写与调试

## 贡献
张嘉树完成此project代码编写
