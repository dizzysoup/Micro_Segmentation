import asyncio
import websockets
import json

async def client():
    uri = 'ws://192.168.173.19:8766'
    async with websockets.connect(uri) as websocket:
        # 要發送的字典
        data_to_send = {
            'message': 'Hello, Server!',
        }

        # 將字典編碼為JSON
        json_data = json.dumps(data_to_send)

        # 透過WebSocket發送JSON訊息
        await websocket.send(json_data)
        print(f'Sent message: {json_data}')

        # 等待回應
        response = await websocket.recv()
        print(f'Received response: {response}')

asyncio.run(client())
