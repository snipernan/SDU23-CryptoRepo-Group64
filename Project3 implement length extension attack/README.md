
## 简介
SM3的长度拓展攻击实现
## 依赖库
用的是project4里自己写的SM3，没有用额外的库。

## 运行结果
![长度拓展攻击](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project3%20implement%20length%20extension%20attack/figure/5c576608fbb110b6a54f528b14ed138.png)

## 使用说明

    length_extension_attack(original_hash, original_length, extension_message, extension_length, extension_hash)
函数接受一个哈希值和原消息的长度，以及需要拓展的消息和拓展消息的长度（其实不必要输入可以自己检测的）。

没有做多格式的消息输入，消息的格式参照代码的消息格式。



## 更新日志
2023.7.25 完成SM3长度拓展攻击

## 贡献
snipernan完成此project代码编写

