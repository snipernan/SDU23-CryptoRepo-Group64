## 简介
在比特币测试网站上发起一笔交易并且追踪交易信息。


## 项目说明
本项目主要分为两个步骤：

-在比特币测试网站上发起交易

-追踪该交易的信息

首先为了在比特币测试网站上发起交易，我们需要安装Bitcoin Core，安装成功后修改其配置文件，使其运行测试分支而非主分支，之后我们等待其同步测试分支区块即可。

![18](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/7e1c8c18-fecd-4d9e-bfb0-be21afaedfa6)

此时我们的账户上比特币数目为0，我们需要到网站上申请测试用的比特币，待我们账户上有比特币后，我们便可以发起一笔自己给自己的比特币交易。

![18_1](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/5d446e27-9561-4197-adf5-5efebda1f4a4)

每一笔交易都有一个对应的Hash值，我们记下我们发起的交易的Hash值，再通过Python获取并记录该笔交易的信息。

这里我们需要一个API来查询交易，这里我们选择Blockstream Explorer。最后我们会获得一个json文件，记录了该笔交易的信息（该文件被记录在bitcoin.txt中）。

![json文件](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/b290fcb8-ed6f-4abb-8628-3f00e83d7be3)


## 运行结果
分析并获得的部分比特币交易信息：

![项目18](https://github.com/snipernan/SDU23-CryptoRepo/assets/111271440/002b1498-ce6a-4137-bc9b-3d97d34972bd)


## 更新日志
2023.7.4 完成Send and parse tx on Bitcoin testnet。

## 贡献
张嘉树完成此project代码编写
