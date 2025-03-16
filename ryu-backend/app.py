from flask import Flask,jsonify,request
from dslmanager import transform_intent_to_dsl
import json
import re
import asyncio
app = Flask(__name__)


# 模擬讀取 intent.txt 和 epg.json 的路徑
INTENT_FILE = 'intent.txt'
EPG_FILE = 'epg.json'


# 讀取 intent.txt
def read_intent_file():
    try:
        with open(INTENT_FILE, 'r') as file:
            intents = file.readlines()
        return [intent.strip() for intent in intents]  # 移除每行末尾的換行符
    except Exception as e:
        print(f"Error reading {INTENT_FILE}: {e}")
        return []

# 讀取 epg.json
def read_epg_json():
    try:
        with open(EPG_FILE, 'r') as file:
            epg_data = json.load(file)
        return epg_data
    except Exception as e:
        print(f"Error reading {EPG_FILE}: {e}")
        return []
    

# 讀取 label.json 檔案的函數
def load_labels():
    try:
        with open('label.json', 'r') as f:
            labels = json.load(f)
        return labels
    except Exception as e:
        return {"error": "Unable to read label.json file", "details": str(e)}
    
# 根據條件過濾出符合的 IP
def get_matching_ips(condition, epg_data):
    matching_ips = []
    category, value = condition.split(": ")
   
    for host in epg_data:
        # 檢查每個host的對應字段是否匹配
        if category == "Function" and value == host['Function']:
            matching_ips.append(host['IP'])
        elif category == "Priority" and value == host['Priority']:
            matching_ips.append(host['IP'])
            print(host['IP'])
        elif category == "Type" and value == host['Type']:
            matching_ips.append(host['IP'])
        elif category == "Security" and value == host['Security']:
            matching_ips.append(host['IP'])
    return matching_ips


# 統一的 /label 路由
@app.route('/datacenter/label/<category>', methods=['GET'])
def get_label(category):
    labels = load_labels()

    # 檢查 category 是否存在於 labels 中
    if category in labels:
        return jsonify(labels[category])
    else:
        return jsonify({"error": f"{category} not found in label.json"}), 404



@app.route('/datacenter/submit_labels', methods=['POST'])
def submit_labels():
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No data provided"}), 400

    print("Received data:", data)
    
    # 提取 host 資料
    host_info = data.get("hostInfo", {})
    ipv4 = host_info.get('ipv4', 'N/A')[0]
    labels = data.get('labels', {})

    # 打印或儲存資料
    print(f"host_info: {host_info}")
    print(f"Labels: {labels}")
    
    # 讀取現有的 epg.json 檔案
    try:
        with open('epg.json', 'r') as file:
            epg_data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        epg_data = []  # 如果檔案不存在或格式錯誤，初始化為空陣列
        
    # 新的標籤資料
    new_label = {
        "IP": ipv4,
        "Function": labels.get("function", "N/A"),
        "Priority": labels.get("priority", "N/A"),
        "Type": labels.get("type", "N/A"),
        "Security": labels.get("security", "N/A")
    }
    
    # 將新標籤資料加到現有資料中
    epg_data.append(new_label)
    
    # 將資料寫回 epg.json 檔案
    with open('epg.json', 'w') as file:
        json.dump(epg_data, file, indent=4)

    return jsonify({"status": "success", "message": "Labels received and processed."})

''' 
  { "method" : "allow",
    "egress" : "Web",
    "egresstype" : "function",
    "port" : 3306,
    "protocol" : "TCP",
    "ingress" : "Database",
    "ingresstype" : "function"
 }
'''
@app.route('/datacenter/intent', methods=['POST'])
async def post_intent():
    data = request.get_json()
    
    method = data.get('method' , '')  # allow or deny
    egresstype = data.get('egresstype','') # egress label
    egress = data.get('egress','')  # egress type   
    protocol = data.get('protocol','') # TCP、UDP、ICMP
    ingresstype = data.get('ingresstype','') # ingress label
    ingress = data.get('ingress','') # ingress
    port = data.get('port') # 3306,22,80..etc..       
    
    with open('intent.txt', 'a') as file :
        file.write(f"{method} {egresstype}:{egress}, {protocol}:{port}, {ingresstype}:{ingress} \n")
    await transform_intent_to_dsl() #把DSL傳送到 Controller
    return "Intent data written to file.", 200

@app.route('/datacenter/dsl/ryu', methods=['GET'])
def get_dsl_ryu():
    result = []
    with open('dsl.txt', 'r') as dsl_file:
        lines = dsl_file.readlines()
    pattern = r"allow \{ (\w+), (\d+\.\d+\.\d+\.\d+), (\d+\.\d+\.\d+\.\d+) \}"
    for line in lines:
        # 使用正則表達式來提取需要的部分
        match = re.match(pattern, line.strip())
        if match:
            protocol = match.group(1)
            egress_ip = match.group(2)
            ingress_ip = match.group(3)
            
            # 建立 JSON 結構
            rule = {
                "allow": {
                    "protocol": protocol,
                    "egress_ip": egress_ip,
                    "ingress_ip": ingress_ip
                }
            }
            result.append(rule)
    return jsonify(result)
    
    

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=5000,debug=True)
