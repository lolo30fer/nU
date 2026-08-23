import requests
import json
import base64
import os
import subprocess
import time
import re
import socket
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# Tabe' baraye Estekhraje link ha
# ==========================================
def extract_links_from_text(text):
    patterns = [r'vless://[^\s<>"\'/]+', r'vmess://[^\s<>"\'/]+', r'trojan://[^\s<>"\'/]+', r'ss://[^\s<>"\'/]+']
    all_links = []
    for p in patterns:
        all_links.extend(re.findall(p, text))
    return list(set(all_links)) # Hazfe tekrari ha

def get_configs_from_url(url, filename="configs.txt"):
    print(f"[*] Dar hale daryafte config ha az URL...")
    try:
        req = requests.get(url, timeout=15)
        all_links = extract_links_from_text(req.text)
        
        with open(filename, "w", encoding="utf-8") as f:
            for link in all_links:
                f.write(link + "\n")
                
        print(f"[*] {len(all_links)} config peyda shod va too '{filename}' zakhire shod.\n")
        return all_links
    except Exception as e:
        print(f"[!] Error daryaft az URL: {e}")
        return []

def get_configs_from_file(filepath, filename="configs.txt"):
    print(f"[*] Dar hale khandane config ha az file '{filepath}'...")
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
            
        all_links = extract_links_from_text(text)
        
        with open(filename, "w", encoding="utf-8") as f:
            for link in all_links:
                f.write(link + "\n")
                
        print(f"[*] {len(all_links)} config peyda shod va too '{filename}' tamiz shod.\n")
        return all_links
    except Exception as e:
        print(f"[!] Error khandane file: {e}")
        return []

# ==========================================
# Marhale 1: TCP Ping (Filtere Sari')
# ==========================================
def extract_address_port(link):
    try:
        protocol = link.split('://')[0]
        if protocol == "vmess":
            encoded = link.replace("vmess://", "").split("#")[0]
            encoded += "=" * ((4 - len(encoded) % 4) % 4)
            data = json.loads(base64.b64decode(encoded).decode('utf-8', errors='ignore'))
            return data.get("add"), int(data.get("port", 443))
        elif protocol == "ss":
            part = link.replace("ss://", "").split("#")[0]
            if "@" not in part:
                part += "=" * ((4 - len(part) % 4) % 4)
                part = base64.b64decode(part).decode('utf-8', errors='ignore')
            addr_port = part.split("@")[-1].replace("/", "")
            return addr_port.split(":")[0], int(addr_port.split(":")[1])
        else:
            parsed = urlparse(link)
            return parsed.hostname, parsed.port or 443
    except:
        return None, None

def tcp_ping(link):
    addr, port = extract_address_port(link)
    if not addr:
        return False, link, None, None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((addr, port))
        sock.close()
        return result == 0, link, addr, port
    except:
        return False, link, addr, port

# ==========================================
# Marhale 2: Xray Config Builder
# ==========================================
def build_xray_config(link, port):
    protocol = link.split('://')[0]
    address = "Unknown"
    outbound = {"protocol": protocol, "settings": {}}
    stream_settings = {"network": "tcp"}

    try:
        if protocol == "vless":
            parsed = urlparse(link)
            uuid = parsed.username
            address = parsed.hostname
            server_port = parsed.port or 443
            params = parse_qs(parsed.query)
            
            outbound["settings"] = {
                "vnext": [{"address": address, "port": server_port, "users": [{"id": uuid, "encryption": "none", "flow": params.get('flow', [''])[0]}]}]
            }
            
            net = params.get('type', ['tcp'])[0]
            sec = params.get('security', [''])[0]
            stream_settings["network"] = net
            
            if net == "ws":
                stream_settings["wsSettings"] = {"path": params.get('path', ['/'])[0], "headers": {"Host": params.get('host', [address])[0]}}
            elif net == "grpc":
                stream_settings["grpcSettings"] = {"serviceName": params.get('serviceName', [''])[0]}
            
            if sec == "reality":
                stream_settings["security"] = "reality"
                stream_settings["realitySettings"] = {
                    "serverName": params.get('sni', [address])[0],
                    "publicKey": params.get('pbk', [''])[0],
                    "shortId": params.get('sid', [''])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0]
                }
            elif sec == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {"serverName": params.get('sni', [address])[0], "fingerprint": params.get('fp', ['chrome'])[0]}

        elif protocol == "vmess":
            encoded = link.replace("vmess://", "")
            encoded += "=" * ((4 - len(encoded) % 4) % 4)
            data = json.loads(base64.b64decode(encoded).decode('utf-8', errors='ignore'))
            address = data.get("add", "Unknown")
            outbound["settings"] = {
                "vnext": [{"address": address, "port": int(data.get("port", 443)), "users": [{"id": data.get("id", ""), "alterId": int(data.get("aid", 0))}]}]
            }
            stream_settings["network"] = data.get("net", "tcp")
            if data.get("net") == "ws":
                stream_settings["wsSettings"] = {"path": data.get("path", "/"), "headers": {"Host": data.get("host", address)}}
            if data.get("tls") == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {"serverName": data.get("sni", address)}

        elif protocol == "trojan":
            parsed = urlparse(link)
            password = parsed.username
            address = parsed.hostname
            server_port = parsed.port or 443
            params = parse_qs(parsed.query)
            outbound["settings"] = {"servers": [{"address": address, "port": server_port, "password": password}]}
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {"serverName": params.get('sni', [address])[0]}
                
        elif protocol == "ss":
            part = link.replace("ss://", "").split("#")[0]
            if "@" not in part:
                part += "=" * ((4 - len(part) % 4) % 4)
                part = base64.b64decode(part).decode('utf-8', errors='ignore')
            method_pass, addr_port = part.split("@")
            addr_port = addr_port.replace("/", "")
            address = addr_port.split(":")[0]
            server_port = int(addr_port.split(":")[1])
            method, password = method_pass.split(":")
            outbound["settings"] = {"servers": [{"address": address, "port": server_port, "method": method, "password": password}]}
    except:
        pass

    outbound["streamSettings"] = stream_settings
    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound]
    }
    return config, protocol, address

def wait_for_port(port, timeout=3):
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                return True
        except:
            pass
        time.sleep(0.1)
    return False

# ==========================================
# Marhale 3: HTTP Request ba Xray
# ==========================================
counter_lock = __import__('threading').Lock()
counter = [0]

def process_request(link, target, target_name):
    with counter_lock:
        counter[0] += 1
        my_index = counter[0]
    
    socks_port = 20000 + (my_index % 5000)
    config_file = f"temp_{my_index}.json"
    
    xray_config, protocol, address = build_xray_config(link, socks_port)
    
    if address == "Unknown":
        return None
        
    try:
        with open(config_file, "w") as f:
            json.dump(xray_config, f)
    except:
        return None
        
    process = None
    try:
        process = subprocess.Popen(
            ["xray.exe", "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        
        if not wait_for_port(socks_port, timeout=3):
            return None
        
        proxies = {
            'http': f'socks5h://127.0.0.1:{socks_port}',
            'https': f'socks5h://127.0.0.1:{socks_port}'
        }
        
        start_time = time.time()
        res = requests.get(target, proxies=proxies, timeout=4, verify=False)
        ping = int((time.time() - start_time) * 1000)
        
        if res.status_code in [200, 204, 301, 302, 307, 403]:
            return f"{my_index}. [{protocol}] {address} -> HTTP OK - {ping}ms > {target_name}"
        else:
            return None
            
    except Exception:
        return None
        
    finally:
        if process:
            try:
                process.kill()
            except:
                pass
        try:
            if os.path.exists(config_file):
                os.remove(config_file)
        except:
            pass

# ==========================================
# Main Menu & Runner - SIMPLIFIED
# ==========================================
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    
    print("=" * 60)
    print("   V2Ray Config Scanner - Fast & Interactive   ")
    print("=" * 60)

    if not os.path.exists("xray.exe"):
        print("[!] KHATA: xray.exe peyda nashod! Lotfan kenare script gharar bedid.")
        exit()

    # Default URL
    default_url = "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html"
    
    # Default Target
    default_target = input("Enter the target URL (default: https://www.google.com): ")
    
    print(f"\n[*] Dar hale daryafte config ha az GitHub...")
    print(f"[*] URL: {default_url}")
    configs = get_configs_from_url(default_url)
    
    if not configs:
        print("[!] Hich configi baraye test peyda nashod.")
        exit()

    print(f"[*] Target: {default_target}\n")
    target_url = default_target
    target_name = "google.com"
    
    overall_start = time.time()
    
    # Marhale 1: TCP Ping
    print(f"[*] Marhale 1: TCP Ping rooye {len(configs)} config...")
    alive_configs = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(tcp_ping, configs)
        for is_alive, link, addr, port in results:
            if is_alive:
                alive_configs.append(link)
    
    print(f"[*] -> {len(alive_configs)} server zende peyda shod.\n")
    if not alive_configs:
        print("[!] Hich server zendei peyda nashod!")
        exit()
    
    # Marhale 2: HTTP Request
    print(f"[*] Marhale 2: Ersale HTTP Request...")
    print("-" * 60)
    
    MAX_WORKERS = 20
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(process_request, link, target_url, target_name) for link in alive_configs]
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                print(result)
    
    total_time = time.time() - overall_start
    print("-" * 60)
    print(f"[*] Tamam shod! Zamane koll: {total_time:.1f} saniye.")