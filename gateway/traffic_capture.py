from scapy.all import *
import socket

# 設定過濾條件，可以根據需求調整
def packet_filter(pkt):
    # 檢查封包是否為 TCP 且端口是 80、443 或 22
    if pkt.haslayer(TCP):
        tcp_layer = pkt.getlayer(TCP)
        # 檢查目標端口或來源端口是否為 80、443 或 22
        if tcp_layer.dport == 80 or tcp_layer.sport == 80:
            print(f"HTTP Packet: {pkt.summary()}")
        elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
            print(f"HTTPS Packet: {pkt.summary()}")
        elif tcp_layer.dport == 22 or tcp_layer.sport == 22:
            print(f"SSH Packet: {pkt.summary()}")

# 開始捕獲網絡流量，過濾指定端口的封包
def capture_traffic():
    print("Starting to capture traffic...")
    # 捕獲所有 TCP 封包，並使用 packet_filter 函數處理
    sniff(prn=packet_filter, filter="tcp", store=0)

if __name__ == "__main__":
    capture_traffic()
