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
    hex_data = "00 00 00 00 aa bb aa aa aa aa aa bb 86 dd 62 4d f7 36 01 81 06 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5c 07 00 00 00 00 00 00 39 22 57 cf a4 00 3a 45 bc 96 ae 90 47 88 4b 31 33 0e cd 6d 0b 3f fb f6 37 fc 1a 4e 9a 98 34 82 44 70 c7 7b 04 01 02 07 10 00 00 00 02 02 06 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 01 0e 00 00 00 00 6c 06 02 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 16 00 08 f8 64 00 00 00 2c 00 0c a9 09 00 00 00 88 00 00 00 00 00 00 00 04 01 09 05 02 00 00 00 3c 09 00 00 00 00 00 00 00 01 00 c9 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 02 00 09 c2 04 00 00 00 0b c9 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c2 04 00 00 00 09 01 01 00 04 01 10 c9 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 44 43 42 41 44 43 42 41 70 04 03 ff 1e dc 00 40 05 16 00 00 00 07 00 00 00 10 00 00 00 01 2b 10 62 af 80 00 00 01 1e 14 83 02 00 00 00 00 00 00 00 03 00 00 00 00 00 00 6a 2b fe 06 e2 d4 c3 d9 00 02 04 02 00 13 12 3e 70 98 31 d6 16 e4 d2 29 c5 31 38 a4 a2 5e 80 00 e3 d8 8e 98 c4 7f 60 d8 f2 f4 86 5a 6b 97 4a 16 a7 5c f0 2a 20 29 59 40 9e b9 72 8f 3e 1f 8e fd a9 1c b4 24 c7"
    output_file = sys.argv[2] if len(sys.argv) > 2 else "packet.pcap"
    
    create_pcap(hex_data, output_file)

if __name__ == "__main__":
    main() 