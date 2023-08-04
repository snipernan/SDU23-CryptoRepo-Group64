
## 简介
SM3优化，将实现结果与openssl库结果进行比对并对比时间。
## 依赖库
OpenSSL 3.1.0

## 运行结果
使用了内联函数，循环展开，重新排序指令这些基础的O2优化，最终优化结果为比openssl快一倍。
![优化结果](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project4%20do%20your%20best%20to%20optimize%20SM3%20implementation%20(software)/figure/dfa9c2fd87ec4a44345b708fbeb4a0c.png)

后来将运算都放入SIMD中，比原有速度减慢2倍左右。原因是SM3的加密流程有很强的数据依赖，SIMD的并行处理无法发挥。查阅文献发现可以通过调整流程进行4个部件的并行处理，仍有优化空间。

## 使用说明
需要在项目中包含openssl的库，如下图：
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/1.png)
![链接](https://github.com/snipernan/SDU23-CryptoRepo/blob/main/Project1%20implement%20the%20na%C3%AFve%20birthday%20attack%20of%20reduced%20SM3/figure/2.png)

## 更新日志
2023.7.25 完成基础版本SM3，比openssl快一倍左右

2023.7.26 增加了压缩函数的SIMD版本，效果不理想，建议使用前一个版本

## 贡献
snipernan完成此project代码编写

