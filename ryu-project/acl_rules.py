##
## 處理ACL 規則相關邏輯
##

from pyparsing import Word, Literal, nums, Group, Optional, Combine

# 定義 DSL 語法規則
action = Literal("allow") | Literal("deny")
protocol = Literal("ping")  # 僅支持 ping 協議（ICMP）

# 定義 IP 地址的每一部分，支持 0-255 範圍
ip_part = Word(nums, min=1, max=3)  # 每一部分應該是一個數字（支持 0-255）
ip = Combine(ip_part + "." + ip_part + "." + ip_part + "." + ip_part)  # 組合成 IP 地址格式

# 源 IP 和目標 IP
src_ip = ip("src_ip")
dst_ip = ip("dst_ip")

# DSL 語法規則
dsl_rule = Group(action("action") + protocol("protocol") + Literal("from") + src_ip("src_ip") + Literal("to") + dst_ip("dst_ip"))

# 解析 DSL 規則
def parse_acl(dsl):
    print(dsl)
    parsed_data = dsl_rule.parseString(dsl)
    return parsed_data
