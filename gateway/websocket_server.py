import asyncio
import websockets
import json
import iptc

# 處理接收到的 WebSocket 訊息
async def handle_message(websocket):
    async for message in websocket:
        try:
            # 解碼JSON訊息
            data = json.loads(message)
            
            
            # 檢查訊息是否包含要設定的 iptables 規則
            if 'egress_ip' in data[0] and 'method' in data[0]:
                # iptables 的目標是 ACCEPT、DROP、REJECT
                rule = {
                    'protocol': data[0]["protocol"],
                    'src' : data[0]['egress_ip'].split(",")[0],
                    'target' : 'ACCEPT' if data[0]["method"].lower() == "allow" else 'DROP',                    
                }
                
                if data[0]["protocol"].lower() == "tcp":
                    rule['tcp'] = {'dport': str(data[0]["port"])}
                elif data[0]["protocol"].lower() == "udp" :
                    rule['udp'] = {'dport': str(data[0]["port"])}
                    
                print(f"Received message: {rule}")
                iptc.easy.insert_rule('filter', 'INPUT', rule)
                print(f"Rule to block traffic from {data[0]['egress_ip']} added successfully!")

                # 回應客戶端規則設定成功的訊息
                response_data = {"response": f"Policy deployed {data[0]['egress_ip']} successfully!"}
            else:
                response_data = {"response": "Invalid data format. Missing 'egreess ip ' or 'method'."}

            # 將回應編碼為JSON並發送回客戶端
            response_message = json.dumps(response_data)
            await websocket.send(response_message)

        except json.JSONDecodeError:
            print("Invalid JSON format")

# 設定 WebSocket 伺服器
async def main():
    async with websockets.serve(handle_message, "0.0.0.0", 8766):
        print('start server: 0.0.0.0:8766')
        await asyncio.Future()  # run forever

asyncio.run(main())
