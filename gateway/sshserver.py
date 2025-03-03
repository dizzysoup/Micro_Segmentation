import paramiko
import socket
import threading

# 設置 SSH 伺服器的主機密鑰
def create_server_key():
    try:
        private_key = paramiko.RSAKey.generate(2048)
        private_key.write_private_key_file('server_key')
        print("成功生成伺服器私鑰。")
    except Exception as e:
        print(f"生成伺服器私鑰失敗: {e}")

# 處理客戶端連接
class SSHServer(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        # 在這裡設置身份驗證邏輯
        #if username == "root" and password == "root":
        #    return paramiko.AUTH_SUCCESSFUL
        #else:
        #    return paramiko.AUTH_FAILED
        
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

# 處理 SSH 會話
def handle_ssh_session(client, server_key):
    try:
        # 創建 transport
        transport = paramiko.Transport(client)
        transport.add_server_key(server_key)
        
        # 進行身份驗證
        server = SSHServer()
        transport.start_server(server=server)

        # 等待客戶端請求命令
        channel = transport.accept()
        if channel is None:
            print("No channel.")
            return
        
        print("SSH 會話已經建立。")

        # 接受客戶端命令並處理
        while True:
            # 接收客戶端發送的命令
            data = channel.recv(1024)
            if not data:
                break
            print(f"收到命令: {data.decode()}")
            # 執行命令並回應
            response = f"命令結果: {data.decode()}"
            channel.send(response.encode())

        print("關閉連接")
        transport.close()

    except Exception as e:
        print(f"發生錯誤: {e}")
        client.close()

# 啟動 SSH 伺服器
def start_ssh_server(host, port):
    # 創建伺服器私鑰（如果不存在）
    try:
        with open("server_key", "r"):
            pass
    except FileNotFoundError:
        create_server_key()
    
    server_key = paramiko.RSAKey.from_private_key_file("server_key")
    
    # 創建 TCP 連接
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(100)
    print(f"SSH 伺服器啟動，監聽端口 {port}...")

    while True:
        client, addr = server_socket.accept()
        print(f"收到來自 {addr} 的連接")
        
        # 在獨立的執行緒中處理連接
        threading.Thread(target=handle_ssh_session, args=(client, server_key)).start()

if __name__ == "__main__":
    # 啟動 SSH 伺服器，監聽 22 端口
    start_ssh_server("0.0.0.0", 22)
