import json
import requests

# 定义一个比特币交易的哈希值
#tx_hash = "db56033647b4bdbf9477cdf11c12f0434371e3cece2e0a132e3b6d5f05eabb70"
tx_hash = "5a7536f5d6d19d45974a05e6baab696df0db9ee4abd1b87696a6f1f31c0d5a4b"
# 发送API请求获取交易信息
response = requests.get(f"https://blockstream.info/api/tx/{tx_hash}")

response.encoding="utf-8"
message=response.text

#打开文件bitcoin.txt，将数据写入记事本中
with open("bitcoin.txt","wb") as f:
     f.write(message.encode("utf-8"))

with open('bitcoin.txt', 'r') as f:
    tx_json_str = f.read()

# 解析JSON信息
tx_data = json.loads(tx_json_str)


# 打印交易信息
print('交易ID:', tx_data['txid'])
print('版本:', tx_data['version'])
print('输入数量:', len(tx_data['vin']))
print('输出数量:', len(tx_data['vout']))
print('交易大小:', tx_data['size'])
print('交易费用:', tx_data['fee'])

