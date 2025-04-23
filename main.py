from scapy.all import ARP, Ether, srp, IP,TCP,sr1,send,conf,get_working_if
import sys
import socket
import requests
import subprocess as sub
from concurrent.futures import ThreadPoolExecutor
import os
import json
import time
import logging

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(SCRIPT_DIR, "oui_cache.json")

def download_oui_database():
    url = "http://standards-oui.ieee.org/oui/oui.txt"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            print("oui数据库下载失败")
    except Exception as e:
        print(f"oui数据库下载失败：{str(e)}")
        return None
def parse_oui_database(oui_data):
    oui_dict = {}
    lines = oui_data.splitlines()
    for line in lines:
        if "(hex)" in line:
            parts = line.split()
            oui = parts[0].replace("-",":").upper()
            company = " ".join(parts[2:])
            oui_dict[oui] = company
    return oui_dict

def load_oui_database():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                cache = json.load(f)
                if "timestamp" in cache and "data" in cache:
                    timestamp = cache.get("timestamp", 0 )
                    if time.time() - timestamp < 60 * 60 * 24 * 7:
                        return cache["data"]
        except json.JSONDecodeError:
            logging.error("缓存格式错误，将重新下载数据库")
    return None

def save_oui_database(oui_dict):
    data = {
        "timestamp": time.time(),
        "data":oui_dict
    }
    with open(CACHE_FILE, 'w') as f:
        json.dump(data, f)

def check_npcap_installed():
    try:
        result = sub.run(["npcap-cli","-v"], capture_output=True, text=True,timeout=2)
        if "Npcap" in result.stdout:
            print("Npcap 已安装")
            return True
        else:
            print("Npcap未安装","检测到Npcap未安装！\n请访问 https://nmap.org/npcap/ 下载并安装Npcap驱动，\n这是Scapy在Windows上运行网络扫描的必要依赖。")
            return False
    except Exception as e:
        print(f"检测Npcap失败：{str(e)}")
        return False

def get_all_ip_info():
    local_ip = get_local_ip()
    public_ip = get_public_ip()
    print("ip信息检测结果：")
    print(f"本地IP地址：{local_ip}")
    print(f"公网IP地址：{public_ip}")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "获取本地IP失败"
    finally:
        s.close()

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org",timeout=5)
        return response.text
    except:
        return "获取公网IP失败"

def scan_network(ip_range , oui_dict):
    # 创建ARP请求包
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    try:
        iface = get_working_if().name
    except:
        print("获取网卡失败")
        return

    try:
        # 发送并接收响应
        result = srp(packet, timeout=3, verbose=0, iface=iface)[0]
    except Exception as e:
        print(f"扫描失败：{str(e)}")
        return

    # 解析结果
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    # 输出结果
    if not devices:
        print("未发现局域网设备！")
    else:
        print(f"{'IP':<18} {'MAC':<18}{'类型':<10}")
        print("-" * 45)
        for device in devices:
            ip = device['ip']
            mac = device['mac']
            device_type = check_is_pc(ip,mac, oui_dict)
            print(f"{device['ip']:<18} {device['mac']:<18}{device_type:<10}")

def is_pc_by_oui(mac, oui_dict):
    oui = mac.split(':')[:3]
    oui_str = ':'.join(oui).upper()

    if oui_str in oui_dict:
        company = oui_dict[oui_str]
        pc_keywords = ["DELL", "HP", "LENOVO", "VMWARE", "MICROSOFT"]
        for keyword in pc_keywords:
            if keyword in company:
                return True
    return False

def is_pc_by_ports(ip):
    pc_ports = [22, 3389, 5900, 8080]
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for port in pc_ports:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            futures.append((executor.submit(sr1, pkt, timeout=1, verbose=0),port))
        for future, port in futures:
            response = future.result()
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags & 0x12:
                    rst_pkt = IP(dst=ip) / TCP(dport=port, flags="R", seq = tcp_layer.ack)
                    send(rst_pkt, verbose=0)
                    return True
    return False

def check_is_pc(ip,mac,oui_dict):
    oui_result = is_pc_by_oui(mac, oui_dict)
    port_result = is_pc_by_ports(ip)
    return "PC" if oui_result or port_result else "非PC"

if __name__ == "__main__":
    check_npcap_installed()
    get_all_ip_info()
    local_ip = get_local_ip()
    if local_ip == "获取本地IP失败":
        sys.exit(1)

    oui_dict = load_oui_database()
    if not oui_dict:
        oui_data = download_oui_database()
        if not oui_data:
            print("无法加载数据库,使用默认OUI列表")
            oui_dict = {
                "00:1A:2B": "Example Company",
                "00:50:56": "VMware, Inc.",
                "00:0C:29": "VMware, Inc.",
                "00:1C:C4": "Dell Inc.",
                "00:1B:44": "Lenovo",
                "00:25:BC": "Hewlett Packard",
            }
        else:
            oui_dict = parse_oui_database(oui_data)
            save_oui_database(oui_dict)
            print(f"成功加载{len(oui_dict)}条OUI数据")
    else:
        print(f"从缓存中加载{len(oui_dict)}条OUI数据")
    ip_parts = local_ip.split('.')[:-1]
    ip_range = '.'.join(ip_parts) + '.0/24'
    scan_network(ip_range, oui_dict)
