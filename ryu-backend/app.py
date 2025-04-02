from flask import Flask,jsonify,request
from dslmanager import transform_intent_to_dsl
from db import get_db_connection
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

# 查詢EPG
def load_epg(ip):
    conn = get_db_connection()
    cursor = conn.cursor()
    sqlstr = """
        SELECT lt.type_name, l.label_value
            FROM epg
            LEFT JOIN label_types lt ON lt.id = epg.label_type_id
            LEFT JOIN labels l ON l.id = epg.label_value_id
            JOIN ep e ON e.id = epg.ip_id
            WHERE e.ip = %s ;
    """ 
    cursor.execute(sqlstr,(ip,))
    results = cursor.fetchall()
    conn.close()
    label_dict = {row[0]: row[1] for row in results}   
    return label_dict

# 讀取 label.json 檔案的函數
def load_labels(category):
    conn = get_db_connection()
    cursor = conn.cursor()
    sqlstr = 'SELECT label_value FROM labels WHERE label_type_id IN (SELECT id FROM label_types WHERE type_name = %s);'
    cursor.execute(sqlstr, (category,))
    results = cursor.fetchall()
    conn.close()
    epg_values = {row[0] for row in results}
    return list(epg_values)

# 把資料插入到EPG之中
def insert_epg(ip , info):   
    conn = get_db_connection()
    cursor = conn.cursor()
    sqlstr = "SELECT id FROM ep WHERE ip = %s"
    cursor.execute(sqlstr,(ip,))
    results = cursor.fetchall()
    if results == []:
        sqlstr = "INSERT INTO ep(ip) values (%s)"
        cursor.execute(sqlstr,(ip,))
        conn.commit()
    
    for label_type, label_value in info.items():
        if label_value == "" :
            label_value = "Null"
        sqlstr = """
            SELECT lt.id AS label_type_id, l.id AS label_value_id
            FROM label_types lt
            JOIN labels l ON l.label_type_id = lt.id
            WHERE lt.type_name = %s
            AND l.label_value = %s;
        """
        cursor.execute(sqlstr, (label_type, label_value))
        label_type_id, label_value_id = cursor.fetchone()
        sqlstr = """
            INSERT INTO epg (ip_id, label_type_id, label_value_id)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE label_value_id = VALUES(label_value_id);
        """
        cursor.execute(sqlstr, (results[0][0], label_type_id, label_value_id,))
        conn.commit()
    conn.close()
    
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


# 取得特定標籤 ex : function,type,,environment,application
@app.route('/datacenter/label/<category>', methods=['GET'])
def get_label(category):
    labels = load_labels(category)
    return jsonify(labels)
    
# 為 IP 去填上標籤
@app.route('/datacenter/submit_labels', methods=['POST'])
def submit_labels():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # 提取 host 資料
    host_info = data.get("hostInfo", {})
    ipv4 = host_info.get('ipv4', 'N/A')[0]
    labels = data.get('labels', {})

    # 打印或儲存資料
    print(f"host_info: {ipv4}")
    print(f"Labels: {labels}")
    
    insert_epg(ipv4 , labels) # 插入到資料庫理面
    
    new_data = {
        "ip": ipv4,
        "function": labels.get("function", "Null"),
        "priority": labels.get("priority", "Null"),
        "type": labels.get("type", "Null"),
        "application": labels.get("application", "Null"),
        "environment" : labels.get("environment","Null")
    }
    
    try:
        with open('epg.json', 'r') as file:
            epg_data = json.load(file)
    except FileNotFoundError:
        # 如果檔案不存在，初始化為空列表
        epg_data = []
    ip_found = False
    for entry in epg_data:        
        if entry['ip'] == ipv4:
            entry.update(new_data)  # 如果 IP 存在，更新該條目
            ip_found = True
            break
    if not ip_found:
        epg_data.append(new_data)
        
    # 將更新後的資料寫回 epg.json
    with open('epg.json', 'w') as file:
        json.dump(epg_data, file, indent=4)

    return jsonify({"status": "success", "message": "Labels received and processed."})

# 查詢特定RP中的RPG內容
@app.route('/datacenter/epg/<ip>', methods=['GET'])
def get_epg(ip):
    epg_values = load_epg(ip)
    return jsonify(epg_values)

''' 
  { 
    "method" : "allow",
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

# 取得所有DSL，用於前端面板模擬
@app.route('/datacenter/dsl', methods=['GET'])
def get_all_dsl():
    function_labels = set()
    edges = []
    line_counter = 1
    with open('dsl.txt', 'r') as dsl_file:
        for line in dsl_file:          
            # 正則表達式：擷取 deny/allow, 協定類型, 端口號和標籤
            match = re.match(r"(deny|allow)\{([A-Za-z]+),\s*([\d\.]+(?:,\s*[\d\.]+)*)\s*\},\s*\{([^}]+)\}", line.strip())
            if match:   
                action = match.group(1)  # 'deny' 或 'allow'
                protocol = match.group(2)  # 協定類型，如 TCP, UDP, ICMP
                ip_addresses = match.group(3).split(',')  # 擷取所有 IP 地址
                labels_in_line = match.group(4).split(',')  # 擷取所有標籤
                # 去除多餘的括號和冒號，並取得標籤的值
                def extract_label(label):
                    # 使用正則去掉括號，並提取冒號後面的標籤名稱
                    match = re.match(r'\((\w+):([a-zA-Z0-9_]+)\)', label.strip())
                    if match:
                        return match.group(1).lower(), match.group(2).lower()  # 返回標籤值並轉為小寫
                    return label.strip().lower(), label.strip().lower()   # 如果沒有匹配，直接返回小寫標籤值
                source_label_type,source_label = extract_label(labels_in_line[1])
                function_labels.add((source_label_type,source_label))
                target_label_type,target_label = extract_label(labels_in_line[2])
                function_labels.add((target_label_type,target_label))
                label = protocol + labels_in_line[0]
                edges.append({
                        "id": f"e{line_counter}-2",
                        "source": source_label,  # 使用 source_label 這裡直接使用標籤名
                        "target": target_label,  # 使用 target_label 這裡直接使用標籤名
                        "label": label
                })
                line_counter += 1
            

    node_data = []
    label_map = {} 
    for idx, (label_type, label_value) in enumerate(function_labels, start=1):
        node_data.append({
            "id": str(idx),
            "type": label_type,
            "label":label_value  # 按要求轉小寫
        })
        label_map[label_value] = str(idx)  # 建立標籤到 ID 的映射
     # 使用標籤映射將 source 和 target 轉換為 ID
    for edge in edges:
        edge["source"] = label_map.get(edge["source"], edge["source"])  # 查找 source 標籤對應的 ID
        edge["target"] = label_map.get(edge["target"], edge["target"])  # 查找 target 標籤對應的 ID
        
    data = {
        "nodes" : node_data , 
        "edges" : edges
    }
    return  jsonify(data)
    

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
