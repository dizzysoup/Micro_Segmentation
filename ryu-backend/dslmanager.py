import json

# 根據條件過濾出符合的 IP
def get_matching_ips(type,label):
    with open('epg.json', 'r') as file:
        data = json.load(file)            
    
    matching_ips = [entry['IP'] for entry in data if entry[type] == label]
    
    return matching_ips
    


# 將intent 轉換成dsl
def transform_intent_to_dsl():
    with open('intent.txt','r') as intent_file:
        intents = intent_file.readlines()
    with open('dsl.txt', 'w') as dsl_file:
        dsl_file.truncate(0)  # 清空文件內容
    # 開啟 dsl.txt 準備寫入
    with open('dsl.txt', 'w') as dsl_file:
        for intent in intents:
            # 解析 intent.txt 中的每一行
            parts = intent.strip().split(",")
            
            # 構建 DSL 格式
            # 假設格式為 "allow function:Web, TCP:3306, function:Database"
            egresstype = parts[0].split(" ")[1].split(":")[0]
            egresslabel = parts[0].split(" ")[1].split(":")[1]           
            
            ingresstype =  parts[2].split(" ")[1].split(":")[0]
            ingresslabel = parts[2].split(" ")[1].split(":")[1]
            
            
            allow = parts[0].split(" ")[0]
            protocol = parts[1].split(":")[0].strip()  # TCP or UDP or ICMP
            egressips = get_matching_ips(egresstype,egresslabel)
            ingressips = get_matching_ips(ingresstype,ingresslabel)
            
            port = parts[1].split(":")[1].strip()  # 3306  
                
            for egress_ip in egressips:
                for ingress_ip in ingressips:                    
                    # 組合為需要的 DSL 格式
                    dsl_line = f"{allow} {{ {protocol}, {egress_ip}, {ingress_ip} }},{{ {port}, ({egresstype}:{egresslabel}),({ingresstype}:{ingresslabel}) }}\n"
                    dsl_file.write(dsl_line)
            