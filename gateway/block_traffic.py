import iptc

rule = {
    'protocol': 'icmp',        #  TCP
    'target': 'DROP',         # 目標是丟棄流量
    'src': '10.0.0.2',        # 來源 IP 是 10.0.0.2
}

iptc.easy.insert_rule('filter', 'INPUT', rule) # 放入到INPUT 鏈、filter 表中

print("Rule to block traffic from 10.0.0.2 added successfully!")