
## 简介
使用查找表实现的生日攻击，使用了openSSL的sm3和openMP的多线程。

## 依赖库
OpenSSL 3.1.0
OpenMP 
## 运行结果
成功在可接受时间内查找了48bit的碰撞，图中可以看到碰撞结果。
![48bit查找结果](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/3.png)

## 使用说明
需要在项目中包含openssl的库，如下图：
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/1.png)
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/2.png)



## 更新日志
2023.7.24 完成生日攻击48bit碰撞搜索
