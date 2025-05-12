#!/usr/bin/env python3
from scapy.all import *
import sys

def create_pcap(hex_data, output_file="packet.pcap"):
    try:
        # 将十六进制字符串转换为字节
        raw_data = bytes.fromhex(hex_data.replace(' ', ''))
        
        # 创建数据包
        packet = Ether(raw_data)
        
        # 将数据包写入pcap文件
        wrpcap(output_file, packet)
        print(f"成功创建pcap文件: {output_file}")
        
    except Exception as e:
        print(f"创建pcap文件时出错: {str(e)}")

def main():
    
    hex_data = "00 00 00 00 00 00 00 00 00 00 00 00 88 a8 3c 00 81 00 36 00 08 00 4f 24 00 df 00 68 00 00 07 06 39 f2 00 00 00 00 40 00 00 00 89 17 d8 00 03 00 00 40 00 00 00 80 03 00 00 00 00 00 00 40 00 00 00 44 3c 88 13 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 40 00 00 00 00 00 ff ff 40 00 00 00 00 00 07 ff 40 00 00 00 00 00 00 08 40 00 00 00 00 00 00 01 00 00 00 00 00 00 00 06 86 3e ff ff ff fd 02 03 87 07 0e f8 2d 1c 25 0b 41 1b b9 b9 71 d2 81 00 0d 0e d1 55 79 7c 93 e3 b0 44 30 8c 02 11 74 5a 0b be d0 7f 7b 46 a2 e8 0f af 4f 65 0f 01 04 de 59 05 02 00 03 93 44 14 33 00 00 00 00 ff 00 00 00 03 00 00 8a 46 00 00 00 00 00 00 00 4e 27 4e 26 39 30 00 00 39 30 00 00 51 a6 01 00 5a 2a 00 00 89 55 36 1a 2e 50 7b 7f 21 10 57 c8 62 3f c0"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "packet.pcap"
    
    create_pcap(hex_data, output_file)

if __name__ == "__main__":
    main() 