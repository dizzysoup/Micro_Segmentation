import json
import requests
import websockets

# 根據條件過濾出符合的 IP
def get_matching_ips(type,label):
    with open('epg.json', 'r') as file:
        data = json.load(file)              
    matching_ips = [entry['IP'] for entry in data if entry[type] == label]
    return matching_ips

# 把策略更新到ryu  
def update_policy_to_ryu():
    result = []
    with open('dsl.txt', 'r') as dsl_file:
        dsls = dsl_file.readlines()
        
        for dsl in dsls:
            parts = dsl.split("},")
            
            method_and_ips = parts[0].strip().split(" ")            
            method = method_and_ips[0].split("{")[0]  # allow           
            protocol = method_and_ips[0].split("{")[1].split(",")[0] # TCP
            
            egress_ip = method_and_ips[1].split(",")[0]  # 192.168.173.102
            ingress_ip = method_and_ips[2]  # 192.168.173.101
            
            policy = {
                "egress_ip": egress_ip,
                "ingress_ip": ingress_ip,
                "protocol": protocol,
                "method": method
            }            
            result.append(policy)
    url = "http://sdn.yuntech.poc.com/ryu/policy"
    print(json.dumps(result,indent=4))
    try:
        # 使用 POST 請求將解析後的結果發送為 JSON
        response = requests.post(url, json=result)
        
        # 檢查回應狀態
        if response.status_code == 200:
            print("Policy successfully updated.")
        else:
            print(f"Failed to update policy. Status code: {response.status_code}")
            print("Response:", response.text)
    
    except requests.exceptions.RequestException as e:
        # 捕捉任何請求異常
        print(f"An error occurred: {e}")

# 把策略更新到iptables
async def update_policy_to_iptables():
    result = []    
    with open('dsl.txt', 'r') as dsl_file:
        dsls = dsl_file.readlines()
        
        for dsl in dsls:
            parts = dsl.split("},")
            
            method_and_ips = parts[0].strip().split(" ")            
            method = method_and_ips[0].split("{")[0]  # allow           
            protocol = method_and_ips[0].split("{")[1].split(",")[0] # TCP
            
            port = parts[1].strip("{}").split(",")[0] # 3306
            if(port == " ") : continue
            
            egress_ip = method_and_ips[1]  # 192.168.173.102 來源
            ingress_ip = method_and_ips[2]  # 192.168.173.103 接收端
            
            policy = {
                "egress_ip": egress_ip,                
                "protocol": protocol,
                "port" : port,
                "method": method
            }            
            result.append(policy)
    # 開啟websocket，要把策略更新到host上的iptables
    
    uri = f'ws://{ingress_ip}:8766'
    print(uri)
    # 資料發送
    async with websockets.connect(uri) as websocket: 
        # 將字典編碼為JSON
        json_data = json.dumps(result)

        # 透過WebSocket發送JSON訊息
        await websocket.send(json_data)
        print(f'Sent message: {json_data}')

        response = await websocket.recv()
        print(f'Received response: {response}')
    
# 將intent 轉換成dsl
async def transform_intent_to_dsl():
    with open('intent.txt','r') as intent_file:
        intents = intent_file.readlines()
   
    # 開啟 dsl.txt 準備寫入    
    with open('dsl.txt', 'w+') as dsl_file:
        for intent in intents:            
            parts = intent.strip().split(",")            
            # 構建 DSL 格式
            # 假設格式為 allow{TCP, 192.168.173.102, 192.168.173.103 },{ 80, (function:Web),(function:Database) }
            egresstype = parts[0].split(" ")[1].split(":")[0]
            egresslabel = parts[0].split(" ")[1].split(":")[1]           
            
            ingresstype =  parts[2].split(" ")[1].split(":")[0]
            ingresslabel = parts[2].split(" ")[1].split(":")[1]
            
            
            allow = parts[0].split(" ")[0]
            protocol = parts[1].split(":")[0].strip()  # TCP or UDP or ICMP
            egressips = get_matching_ips(egresstype,egresslabel)
            ingressips = get_matching_ips(ingresstype,ingresslabel)
            
            port = parts[1].split(":")[1].strip()  # 3306  
            print(ingressips)
            for egress_ip in egressips:
                for ingress_ip in ingressips:                    
                    # 組合為需要的 DSL 格式
                    dsl_line = f"{allow}{{{protocol}, {egress_ip}, {ingress_ip} }},{{ {port}, ({egresstype}:{egresslabel}),({ingresstype}:{ingresslabel}) }}\n"
                    
                    dsl_file.write(dsl_line)
    if protocol == 'ICMP' :
        update_policy_to_ryu() # policy 更新到RyuController
    if protocol == 'TCP' :
        await update_policy_to_iptables() # policy 更新到iptables
            