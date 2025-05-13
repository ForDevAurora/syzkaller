#!/usr/bin/env python3
from scapy.all import *
import sys
import os

def analyze_packet(hex_data):
    try:
        # 将十六进制字符串转换为字节
        raw_data = bytes.fromhex(hex_data.replace(' ', ''))
        
        # 使用scapy解析数据包
        packet = Ether(raw_data)
        
        # 打印基本信息
        print("\n=== 数据包分析 ===")
        print(f"以太网类型: {packet.type}")
        print(f"源MAC: {packet.src}")
        print(f"目标MAC: {packet.dst}")
        
        # 检查是否是IP包
        if IP in packet:
            print("\n=== IP头部 ===")
            print(f"版本: {packet[IP].version}")
            print(f"源IP: {packet[IP].src}")
            print(f"目标IP: {packet[IP].dst}")
            print(f"协议: {packet[IP].proto}")
            print(f"TTL: {packet[IP].ttl}")
            
            # 检查是否是TCP包
            if TCP in packet:
                print("\n=== TCP头部 ===")
                print(f"源端口: {packet[TCP].sport}")
                # 标示出它原始在包中的位置，以及16进制
                # 获取TCP头部在原始数据包中的偏移位置
                tcp_offset = len(packet) - len(packet[TCP])
                tcp_sport_offset = tcp_offset + 0  # 源端口在TCP头部开始处
                tcp_sport_bytes = raw_data[tcp_sport_offset:tcp_sport_offset+2]
                print(f"源端口位置: {tcp_sport_offset}-{tcp_sport_offset+1}")
                print(f"源端口原始值(hex): {tcp_sport_bytes.hex(' ').upper()}")
                print(f"目标端口: {packet[TCP].dport}")
                # 标示出它原始在包中的位置，以及16进制
                tcp_dport_offset = tcp_offset + 2  # 目标端口在TCP头部开始处
                tcp_dport_bytes = raw_data[tcp_dport_offset:tcp_dport_offset+2]
                print(f"目标端口位置: {tcp_dport_offset}-{tcp_dport_offset+1}")
                print(f"目标端口原始值(hex): {tcp_dport_bytes.hex(' ').upper()}")
                print(f"序列号: {packet[TCP].seq}")
                print(f"确认号: {packet[TCP].ack}")
                print(f"标志: {packet[TCP].flags}")
                
            # 检查是否是UDP包
            elif UDP in packet:
                print("\n=== UDP头部 ===")
                print(f"源端口: {packet[UDP].sport}")
                print(f"目标端口: {packet[UDP].dport}")
                print(f"长度: {packet[UDP].len}")
        
        # 打印原始数据
        print("\n=== 原始数据 ===")
        print(hexdump(packet, dump=True))
        # Save the packet to a pcap file
        pcap_file = "packet.pcap"
        wrpcap(pcap_file, packet)
        print(f"数据包已保存到 {pcap_file}")

    except Exception as e:
        print(f"解析错误: {str(e)}")

def main():
    print("请输入十六进制数据包（用空格分隔，例如：aa bb cc dd）")
    print("输入 'q' 退出")
    
    while True:
        try:
            user_input = input("\n> ")
            if user_input.lower() == 'q':
                break
                
            if not user_input.strip():
                continue
                
            analyze_packet(user_input)
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"错误: {str(e)}")
    # Save the packet to a file
   

if __name__ == "__main__":
    main() 
'''
38 d2 f1 d3 e3 4a aa aa aa aa aa bb 81 00 0a 00 08 00 45 f9 10 3c 00 65 00 00 07 06 e1 8f 00 00 00 

'''