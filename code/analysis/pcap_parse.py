#!/usr/bin/env python
import os
import sys
import struct
import ipaddress
from scapy.all import rdpcap, TCP, Raw, DNS, DNSQR, IP

outputdir="D:\\Documents\\Working\\实验室\\赌博诈骗apk处理\\resultnew\\nowlan\\"
input_dir = "D:\\Documents\\Working\\实验室\\赌博诈骗apk处理\\Pictures2new"


def parse_tls_sni(payload):
    try:
        if len(payload) < 5:
            return None
        # TLS Record Header：1字节 ContentType、2字节 Version、2字节 Length
        content_type = payload[0]
        if content_type != 22:  # 22 表示 Handshake 记录
            return None
        record_length = struct.unpack('!H', payload[3:5])[0]
        if len(payload) < 5 + record_length:
            return None

        # Handshake 消息头：1字节 HandshakeType + 3字节 消息长度
        handshake_type = payload[5]
        if handshake_type != 1:  # 1 表示 ClientHello
            return None
        handshake_length = int.from_bytes(payload[6:9], byteorder='big')
        pos = 9  # ClientHello 消息体起始位置

        if len(payload) < pos + handshake_length:
            return None

        # 跳过 ClientHello 固定字段：
        # 版本 (2字节) + 随机数 (32字节)
        pos += 2 + 32

        # SessionID 长度及 SessionID
        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        # Cipher Suites 长度（2字节）及列表
        if pos + 2 > len(payload):
            return None
        cipher_suites_length = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_length

        # Compression Methods 长度（1字节）及列表
        if pos >= len(payload):
            return None
        compression_methods_length = payload[pos]
        pos += 1 + compression_methods_length

        # Extensions 长度（2字节）
        if pos + 2 > len(payload):
            return None
        extensions_length = struct.unpack('!H', payload[pos:pos + 2])[0]
        pos += 2
        end_extensions = pos + extensions_length

        # 遍历各个扩展项
        while pos + 4 <= end_extensions:
            # 扩展项头部：2字节类型和2字节长度
            ext_type = struct.unpack('!H', payload[pos:pos + 2])[0]
            ext_length = struct.unpack('!H', payload[pos + 2:pos + 4])[0]
            pos += 4
            # 如果扩展类型为 0，则为 SNI 扩展
            if ext_type == 0:
                if pos + 2 > end_extensions:
                    return None
                # Server Name List 长度
                server_name_list_length = struct.unpack('!H', payload[pos:pos + 2])[0]
                pos += 2
                list_end = pos + server_name_list_length
                while pos + 3 <= list_end:
                    # 每个 server name entry：1字节 name_type, 2字节 name_length, 后续 name_length 字节的名称
                    name_type = payload[pos]
                    name_length = struct.unpack('!H', payload[pos + 1:pos + 3])[0]
                    pos += 3
                    if pos + name_length > list_end:
                        return None
                    if name_type == 0:  # 0 表示 host_name
                        server_name = payload[pos:pos + name_length].decode('utf-8', errors='ignore')
                        return server_name
                    pos += name_length
                return None
            else:
                pos += ext_length
        return None
    except Exception:
        return None


def extract_dns_query(pkt):
    """
    提取 DNS 请求报文中的查询域名（qname）。
    """
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode(errors='ignore')
        return qname.rstrip('.')  # 去掉末尾的点
    return None


def extract_http_info(pkt):
    if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
        return None
    try:
        payload = pkt[Raw].load.decode('utf-8', errors='ignore')
    except Exception:
        return None

    if not (payload.startswith('GET') or payload.startswith('POST') or
            payload.startswith('HEAD') or payload.startswith('PUT') or
            payload.startswith('DELETE') or payload.startswith('OPTIONS')):
        return None

    lines = payload.splitlines()
    if not lines:
        return None

    # 解析 Request Line
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2:
        return None
    method = parts[0]
    path = parts[1]

    host = None
    # 查找 Host 头字段
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break

    if not host:
        return None

    # 构造完整 URI（默认采用 http 协议）
    full_uri = "http://{}{}".format(host, path)
    return {"full_uri": full_uri, "host": host, "path": path, "method": method}


def is_public_ip(ip_str):
    """
    判断给定的 IP 地址字符串是否属于公网地址，
    排除私有IP、回环地址及保留地址。
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved)
    except ValueError:
        return False


def process_pcap_file(pcap_file):
    '''if len(sys.argv) < 2:
        print("Usage: {} <pcap_file>".format(sys.argv[0]))
        sys.exit(1)

    pcap_file = sys.argv[1]
    print("Reading pcap file: {}".format(pcap_file))
    pcap_file = sys.argv[1]
'''

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print("Failed to read pcap file: {}".format(e))
        sys.exit(1)

    # 用 set 存储去重后的 SNI、DNS 查询和 HTTP Host 信息
    sni_set = set()
    dns_set = set()
    http_host_set = set()
    # 同时将 HTTP 的详细信息（full_uri, host, path）存入 set（以 tuple 形式存储）
    http_info_set = set()
    # 存储公网 IP 地址
    public_ip_set = set()

    # 遍历所有数据包进行解析
    for pkt in packets:
        # 提取 TLS SNI (从 TCP Raw 层解析)
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            raw_payload = bytes(pkt[Raw].load)
            sni = parse_tls_sni(raw_payload)
            if sni:
                sni_set.add(sni)

        # 提取 DNS 查询
        dns_q = extract_dns_query(pkt)
        if dns_q:
            dns_set.add(dns_q)

        # 提取 HTTP 请求信息
        http_info = extract_http_info(pkt)
        if http_info:
            http_info_set.add((http_info["full_uri"], http_info["host"], http_info["path"]))
            http_host_set.add(http_info["host"])

        # 提取 IP 层中的源和目的 IP，过滤出公网地址
        if pkt.haslayer(IP):
            for ip_str in (pkt[IP].src, pkt[IP].dst):
                if is_public_ip(ip_str):
                    public_ip_set.add(ip_str)

    # 组合全部主机的网络信息，取 SNI、DNS、HTTP Host 与公网 IP 的并集
    all_hosts = sni_set.union(dns_set, http_host_set)

    # 将所有结果写入到一个 txt 文件中
    base_filename = os.path.basename(pcap_file)  # 如 "com.ypjy.app.nunud.android.pcap"
    name, _ = os.path.splitext(base_filename)  # 提取文件名部分 "com.ypjy.app.nunud.android"
    output_file = outputdir+name + ".txt"  # 输出文件 "com.ypjy.app.nunud.android.txt"
    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("======== TLS SNI Names ========\n")
            if sni_set:
                for name in sorted(sni_set):
                    f.write(name + "\n")
            else:
                f.write("None\n")

            f.write("\n======== DNS Query Names ========\n")
            if dns_set:
                for name in sorted(dns_set):
                    f.write(name + "\n")
            else:
                f.write("None\n")

            f.write("\n======== HTTP Request Information ========\n")
            if http_info_set:
                for full_uri, host, path in sorted(http_info_set):
                    f.write("Full URI: {}\nHost: {}\nPath: {}\n\n".format(full_uri, host, path))
            else:
                f.write("None\n")

            f.write("\n======== Public IP Addresses ========\n")
            if public_ip_set:
                for ip in sorted(public_ip_set, key=lambda x: ipaddress.ip_address(x)):
                    f.write(ip + "\n")
            else:
                f.write("None\n")

            f.write("\n======== All Host Network Information (Union) ========\n")
            if all_hosts:
                for host in sorted(all_hosts):
                    f.write(host + "\n")
            else:
                f.write("None\n")
        print("All results have been written to '{}'".format(output_file))
    except Exception as e:
        print("Failed to write results to file: {}".format(e))
        sys.exit(1)


def main():
    if not os.path.isdir(input_dir):
        print("Error: {} is not a directory.".format(input_dir))
        sys.exit(1)

    # 遍历目录中所有 pcap 文件，扩展名不区分大小写
    for file in os.listdir(input_dir):
        if file.lower().endswith(".pcap"):
            pcap_path = os.path.join(input_dir, file)
            process_pcap_file(pcap_path)


if __name__ == '__main__':
    main()
    # process_pcap_file("/Users/gyc/Downloads/realtraffic.pcap")