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
            print(f"Received message: {data}")

            # 檢查訊息是否包含要設定的 iptables 規則
            if 'src' in data and 'target' in data:
                # 根據訊息來設定iptables 規則
                rule = {
                    'protocol': data.get('protocol', 'icmp'),  # 默認使用 icmp 協議
                    'target': data['target'],  # 目標為 DROP
                    'src': data['src'],  # 來源 IP
                }

                # 將規則添加到 INPUT 鏈、filter 表中
                iptc.easy.insert_rule('filter', 'INPUT', rule)
                print(f"Rule to block traffic from {data['src']} added successfully!")

                # 回應客戶端規則設定成功的訊息
                response_data = {"response": f"Blocked traffic from {data['src']} successfully!"}
            else:
                response_data = {"response": "Invalid data format. Missing 'src' or 'target'."}

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
