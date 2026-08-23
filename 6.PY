import requests
import json
import base64
import os
import subprocess
import time
import re
import socket
import threading
import shutil
import html
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================
# Default Configuration
# ==========================================
SAVE_FULL_RESPONSE_DEFAULT = True
MAX_WORKERS_DEFAULT = 32
TCP_WORKERS_DEFAULT = 150
TIMEOUT_DEFAULT = 5
MAX_RESPONSE_CHARS_DEFAULT = 0  # 0 یعنی کامل ذخیره شود

FULL_RESULTS_FILE = "full_results.txt"
WORKING_CONFIGS_FILE = "working_configs.txt"
RESPONSES_DIR = "responses"

# ==========================================
# Global Locks / State
# ==========================================
file_lock = threading.Lock()
counter_lock = threading.Lock()
working_lock = threading.Lock()

counter = [0]
working_list = []
XRAY_BIN = None


# ==========================================
# Request Spec
# ==========================================
@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict
    body: bytes
    raw_http_version: str = "HTTP/1.1"


# ==========================================
# Helper Functions
# ==========================================
def ask_int(prompt, default, min_value=1):
    value = input(f"{prompt} [Default: {default}]: ").strip()
    if not value:
        return default
    try:
        value = int(value)
        if value < min_value:
            return default
        return value
    except:
        return default


def ask_float(prompt, default, min_value=0.1):
    value = input(f"{prompt} [Default: {default}]: ").strip()
    if not value:
        return default
    try:
        value = float(value)
        if value < min_value:
            return default
        return value
    except:
        return default


def ask_bool(prompt, default=True):
    d = "y" if default else "n"
    value = input(f"{prompt} [y/n Default: {d}]: ").strip().lower()
    if not value:
        return default
    return value in ["y", "yes", "1", "true"]


def normalize_scheme(scheme):
    scheme = scheme.strip().lower().replace("://", "")
    if scheme not in ["http", "https"]:
        scheme = "https"
    return scheme


def find_xray():
    candidates = []

    if os.name == "nt":
        candidates.append(os.path.abspath("xray.exe"))
    else:
        candidates.append(os.path.abspath("./xray"))

    candidates.extend([
        "/usr/bin/xray",
        "/usr/local/bin/xray",
        shutil.which("xray")
    ])

    for c in candidates:
        if c and os.path.exists(c):
            return c

    return None


def prepare_output_files(save_full_response=True):
    for f in [FULL_RESULTS_FILE, WORKING_CONFIGS_FILE]:
        if os.path.exists(f):
            os.remove(f)

    if save_full_response:
        if not os.path.exists(RESPONSES_DIR):
            os.makedirs(RESPONSES_DIR)
        else:
            for name in os.listdir(RESPONSES_DIR):
                path = os.path.join(RESPONSES_DIR, name)
                try:
                    if os.path.isfile(path):
                        os.remove(path)
                except:
                    pass


def write_block(text):
    with file_lock:
        print(text)
        with open(FULL_RESULTS_FILE, "a", encoding="utf-8", errors="ignore") as f:
            f.write(text + "\n")


def extract_links_from_text(text):
    text = html.unescape(text)

    pattern = r'(?:vless|vmess|trojan|ss)://[^\s<>"\']+'
    links = re.findall(pattern, text)

    cleaned = []
    for link in links:
        link = link.strip()
        link = link.rstrip("),];")
        cleaned.append(link)

    return list(set(cleaned))


def extract_address_port(link):
    try:
        protocol = link.split('://')[0]

        if protocol == "vmess":
            encoded = link.split('://', 1)[1].split("#")[0]
            encoded += "=" * ((4 - len(encoded) % 4) % 4)
            data = json.loads(base64.b64decode(encoded).decode('utf-8', errors='ignore'))
            return data.get("add"), int(data.get("port", 443))

        elif protocol == "ss":
            part = link.split('://', 1)[1].split("#")[0]

            if "@" not in part:
                part += "=" * ((4 - len(part) % 4) % 4)
                part = base64.b64decode(part).decode('utf-8', errors='ignore')

            addr_port = part.split("@")[-1].split("/")[0]
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
        sock.settimeout(2)
        result = sock.connect_ex((addr, port))
        sock.close()
        return result == 0, link, addr, port
    except:
        return False, link, addr, port


def get_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_for_port(port, timeout=3):
    start = time.time()

    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)

            if sock.connect_ex(('127.0.0.1', port)) == 0:
                sock.close()
                return True

            sock.close()
        except:
            pass

        time.sleep(0.1)

    return False


# ==========================================
# Raw HTTP Request Parser
# ==========================================
def parse_raw_http_request_file(filepath, default_scheme="https"):
    with open(filepath, "rb") as f:
        raw = f.read()

    return parse_raw_http_request(raw, default_scheme=default_scheme)


def parse_raw_http_request(raw_bytes, default_scheme="https"):
    default_scheme = normalize_scheme(default_scheme)

    if b"\r\n\r\n" in raw_bytes:
        head_bytes, body = raw_bytes.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw_bytes:
        head_bytes, body = raw_bytes.split(b"\n\n", 1)
    else:
        head_bytes = raw_bytes
        body = b""

    head_text = head_bytes.decode("iso-8859-1", errors="ignore")
    head_text = head_text.replace("\r\n", "\n").replace("\r", "\n")
    lines = head_text.split("\n")

    if not lines or not lines[0].strip():
        raise ValueError("فایل ریکوئست معتبر نیست؛ خط اول Request Line ندارد.")

    request_line = lines[0].strip()
    parts = request_line.split()

    if len(parts) < 2:
        raise ValueError("Request Line نامعتبر است.")

    method = parts[0].upper()
    target = parts[1]
    raw_http_version = parts[2] if len(parts) >= 3 else "HTTP/1.1"

    headers = {}
    current_header = None

    for line in lines[1:]:
        if not line.strip():
            continue

        # Header continuation
        if line.startswith((" ", "\t")) and current_header:
            headers[current_header] += " " + line.strip()
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()

        # HTTP/2 pseudo headers
        if key.startswith(":"):
            continue

        # این‌ها را requests خودش درست تنظیم کند
        if key.lower() in [
            "content-length",
            "transfer-encoding",
            "connection",
            "proxy-connection"
        ]:
            continue

        if key in headers:
            sep = "; " if key.lower() == "cookie" else ", "
            headers[key] += sep + value
        else:
            headers[key] = value

        current_header = key

    host = None
    for k, v in headers.items():
        if k.lower() == "host":
            host = v
            break

    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        if not host:
            raise ValueError("در Raw Request هدر Host وجود ندارد.")

        if not target.startswith("/"):
            target = "/" + target

        url = f"{default_scheme}://{host}{target}"

    return RequestSpec(
        method=method,
        url=url,
        headers=headers,
        body=body,
        raw_http_version=raw_http_version
    )


def build_simple_request(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed = urlparse(url)

    headers = {
        "Host": parsed.netloc,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Upgrade-Insecure-Requests": "1"
    }

    return RequestSpec(
        method="GET",
        url=url,
        headers=headers,
        body=b"",
        raw_http_version="HTTP/1.1"
    )


def get_request_path_for_display(url):
    parsed = urlparse(url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path


def format_request_for_output(req_spec):
    parsed = urlparse(req_spec.url)
    path = get_request_path_for_display(req_spec.url)

    lines = []
    lines.append(f"{req_spec.method} {path} {req_spec.raw_http_version}")

    has_host = False
    for k in req_spec.headers:
        if k.lower() == "host":
            has_host = True
            break

    if not has_host:
        lines.append(f"Host: {parsed.netloc}")

    for k, v in req_spec.headers.items():
        lines.append(f"{k}: {v}")

    lines.append("")

    if req_spec.body:
        try:
            body_text = req_spec.body.decode("utf-8", errors="replace")
        except:
            body_text = str(req_spec.body)

        lines.append(body_text)

    return "\n".join(lines)


# ==========================================
# Response Formatter
# ==========================================
def get_response_http_version(res):
    try:
        version = res.raw.version
        if version == 10:
            return "HTTP/1.0"
        elif version == 11:
            return "HTTP/1.1"
        elif version == 20:
            return "HTTP/2"
    except:
        pass

    return "HTTP/?"


def decode_response_body(res):
    content = res.content or b""

    if not content:
        return ""

    encoding = res.encoding or res.apparent_encoding or "utf-8"

    try:
        return content.decode(encoding, errors="replace")
    except:
        return content.decode("utf-8", errors="replace")


def format_full_response(res, max_chars=0):
    lines = []

    version = get_response_http_version(res)
    lines.append(f"{version} {res.status_code} {res.reason}")

    for k, v in res.headers.items():
        lines.append(f"{k}: {v}")

    lines.append("")

    body_text = decode_response_body(res)

    if max_chars and max_chars > 0 and len(body_text) > max_chars:
        body_text = body_text[:max_chars] + f"\n\n...[TRUNCATED: showed {max_chars} chars]..."

    lines.append(body_text)

    return "\n".join(lines)


def safe_filename(text, max_len=80):
    text = re.sub(r"[^a-zA-Z0-9._-]+", "_", text)
    return text[:max_len].strip("_") or "result"


# ==========================================
# Xray Config Builder
# ==========================================
def build_xray_config(link, port):
    protocol = link.split('://')[0]
    address = "Unknown"

    outbound = {
        "protocol": protocol,
        "settings": {}
    }

    stream_settings = {
        "network": "tcp"
    }

    try:
        if protocol == "vless":
            parsed = urlparse(link)

            uuid = parsed.username
            address = parsed.hostname
            server_port = parsed.port or 443
            params = parse_qs(parsed.query)

            outbound["settings"] = {
                "vnext": [
                    {
                        "address": address,
                        "port": server_port,
                        "users": [
                            {
                                "id": uuid,
                                "encryption": "none",
                                "flow": params.get('flow', [''])[0]
                            }
                        ]
                    }
                ]
            }

            net = params.get('type', ['tcp'])[0]
            sec = params.get('security', [''])[0]

            stream_settings["network"] = net

            if net == "ws":
                stream_settings["wsSettings"] = {
                    "path": params.get('path', ['/'])[0],
                    "headers": {
                        "Host": params.get('host', [address])[0]
                    }
                }

            elif net == "grpc":
                stream_settings["grpcSettings"] = {
                    "serviceName": params.get('serviceName', [''])[0]
                }

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
                stream_settings["tlsSettings"] = {
                    "serverName": params.get('sni', [address])[0],
                    "fingerprint": params.get('fp', ['chrome'])[0]
                }

        elif protocol == "vmess":
            encoded = link.replace("vmess://", "").split("#")[0]
            encoded += "=" * ((4 - len(encoded) % 4) % 4)

            data = json.loads(base64.b64decode(encoded).decode('utf-8', errors='ignore'))

            address = data.get("add", "Unknown")

            outbound["settings"] = {
                "vnext": [
                    {
                        "address": address,
                        "port": int(data.get("port", 443)),
                        "users": [
                            {
                                "id": data.get("id", ""),
                                "alterId": int(data.get("aid", 0))
                            }
                        ]
                    }
                ]
            }

            stream_settings["network"] = data.get("net", "tcp")

            if data.get("net") == "ws":
                stream_settings["wsSettings"] = {
                    "path": data.get("path", "/"),
                    "headers": {
                        "Host": data.get("host", address)
                    }
                }

            if data.get("tls") == "tls":
                stream_settings["security"] = "tls"
                stream_settings["tlsSettings"] = {
                    "serverName": data.get("sni", address)
                }

        elif protocol == "trojan":
            parsed = urlparse(link)

            password = parsed.username
            address = parsed.hostname
            server_port = parsed.port or 443
            params = parse_qs(parsed.query)

            outbound["settings"] = {
                "servers": [
                    {
                        "address": address,
                        "port": server_port,
                        "password": password
                    }
                ]
            }

            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {
                "serverName": params.get('sni', [address])[0]
            }

        elif protocol == "ss":
            part = link.replace("ss://", "").split("#")[0]

            if "@" not in part:
                part += "=" * ((4 - len(part) % 4) % 4)
                part = base64.b64decode(part).decode('utf-8', errors='ignore')

            method_pass, addr_port = part.split("@", 1)
            addr_port = addr_port.split("/")[0]

            address = addr_port.split(":")[0]
            server_port = int(addr_port.split(":")[1])

            method, password = method_pass.split(":", 1)

            outbound["settings"] = {
                "servers": [
                    {
                        "address": address,
                        "port": server_port,
                        "method": method,
                        "password": password
                    }
                ]
            }

    except:
        pass

    outbound["streamSettings"] = stream_settings

    config = {
        "log": {
            "loglevel": "none"
        },
        "inbounds": [
            {
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "udp": False
                }
            }
        ],
        "outbounds": [
            outbound
        ]
    }

    return config, protocol, address


# ==========================================
# Main Test Function
# ==========================================
def process_request(link, req_spec, timeout, save_full_response, max_response_chars):
    global XRAY_BIN

    with counter_lock:
        counter[0] += 1
        my_index = counter[0]

    socks_port = get_free_port()
    config_file = f"temp_{my_index}.json"

    xray_config, protocol, address = build_xray_config(link, socks_port)

    if address == "Unknown":
        return None

    try:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(xray_config, f)
    except:
        return None

    process = None

    try:
        process = subprocess.Popen(
            [XRAY_BIN, "-c", config_file],
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

        # گرفتن IP خروجی
        try:
            exit_ip = requests.get(
                "https://api.ipify.org",
                proxies=proxies,
                timeout=4,
                verify=False
            ).text.strip()
        except:
            exit_ip = "Unknown"

        # ارسال ریکوئست اصلی
        start_time = time.time()

        res = requests.request(
            method=req_spec.method,
            url=req_spec.url,
            headers=dict(req_spec.headers),
            data=req_spec.body if req_spec.body else None,
            proxies=proxies,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )

        ping = int((time.time() - start_time) * 1000)

        target_host = urlparse(req_spec.url).netloc

        result_line = (
            f"✅ [{ping}ms] "
            f"{protocol} | Server: {address} | "
            f"Outbound IP: {exit_ip} | "
            f"Target: {target_host} | "
            f"Status: {res.status_code} {res.reason} | "
            f"Response Length: {len(res.content)} bytes"
        )

        request_text = format_request_for_output(req_spec)
        response_text = format_full_response(res, max_chars=max_response_chars)

        block_parts = [
            result_line,
            f"🔗 Config:",
            link,
            "",
            f"🌐 Final URL:",
            req_spec.url,
            ""
        ]

        if save_full_response:
            block_parts.extend([
                "📤 Sent Request:",
                request_text,
                "",
                "📥 Full Response:",
                response_text,
                ""
            ])

        block_parts.append("-" * 90)

        block = "\n".join(block_parts)
        write_block(block)

        if save_full_response:
            filename_base = safe_filename(f"{my_index}_{protocol}_{target_host}_{ping}ms_{res.status_code}")
            response_file = os.path.join(RESPONSES_DIR, filename_base + ".txt")

            with open(response_file, "w", encoding="utf-8", errors="ignore") as f:
                f.write(block)

        with working_lock:
            working_list.append((ping, res.status_code, len(res.content), link))

        return True

    except Exception:
        return None

    finally:
        if process:
            try:
                process.kill()
                process.wait(timeout=1)
            except:
                pass

        try:
            os.remove(config_file)
        except:
            pass


# ==========================================
# Main Application
# ==========================================
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    print("=" * 90)
    print("   ⚡ Fast & Complete V2Ray Config Scanner With Custom Request   ")
    print("=" * 90)

    XRAY_BIN = find_xray()

    if not XRAY_BIN:
        print("[!] Error: xray executable not found!")
        print("    Put xray/xray.exe near script or install it in PATH.")
        exit()

    print(f"[*] Xray found: {XRAY_BIN}")

    print("\nSettings:")
    full_workers = ask_int("Full test threads", MAX_WORKERS_DEFAULT, min_value=1)
    tcp_workers = ask_int("TCP ping filter threads", TCP_WORKERS_DEFAULT, min_value=1)
    timeout = ask_float("Request timeout seconds", TIMEOUT_DEFAULT, min_value=0.5)
    save_full_response = ask_bool("Save full response", SAVE_FULL_RESPONSE_DEFAULT)

    max_response_chars = MAX_RESPONSE_CHARS_DEFAULT
    if save_full_response:
        max_response_chars = ask_int(
            "Max response chars to save; 0 means full",
            MAX_RESPONSE_CHARS_DEFAULT,
            min_value=0
        )

    prepare_output_files(save_full_response=save_full_response)

    # ==========================================
    # Config Source
    # ==========================================
    print("\nConfig Source:")
    print("1. From URL / Subscription")
    print("2. From Local File")

    choice = input("\nEnter choice (1/2): ").strip()

    configs = []

    if choice == '1':
        url = input("\nEnter config source URL: ").strip()

        if not url:
            url = "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html"

        print(f"[*] Fetching from {url}")

        try:
            req = requests.get(url, timeout=15, verify=False)
            configs = extract_links_from_text(req.text)
        except Exception as e:
            print(f"[!] Failed to fetch configs: {e}")
            exit()

    elif choice == '2':
        filepath = input("\nEnter config file path: ").strip()

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                configs = extract_links_from_text(f.read())
        except Exception as e:
            print(f"[!] Failed to read config file: {e}")
            exit()

    else:
        print("[!] Invalid selection")
        exit()

    print(f"\n[*] Total configs found: {len(configs)}")

    if len(configs) == 0:
        print("[!] No configs found.")
        exit()

    # ==========================================
    # Request Source
    # ==========================================
    print("\nRequest Mode:")
    print("1. Simple URL GET")
    print("2. Raw HTTP Request File")

    req_choice = input("\nEnter request mode (1/2): ").strip()

    try:
        if req_choice == "1":
            target_url = input("\nEnter target URL, example https://example.com/path: ").strip()

            if not target_url:
                target_url = "https://google.com"

            req_spec = build_simple_request(target_url)

        elif req_choice == "2":
            request_file = input("\nEnter raw request file path, example request.txt: ").strip()
            default_scheme = input("Default scheme for raw request Host, http/https [Default: https]: ").strip()

            if not default_scheme:
                default_scheme = "https"

            req_spec = parse_raw_http_request_file(
                request_file,
                default_scheme=default_scheme
            )

        else:
            print("[!] Invalid request mode")
            exit()

    except Exception as e:
        print(f"[!] Failed to parse request: {e}")
        exit()

    target_name = urlparse(req_spec.url).netloc

    print("\n[*] Request loaded:")
    print("-" * 90)
    print(format_request_for_output(req_spec))
    print("-" * 90)
    print(f"[*] Final URL: {req_spec.url}")

    # ==========================================
    # Stage 1: TCP Filter
    # ==========================================
    print(f"\n[*] Stage 1: Running fast TCP ping filter with {tcp_workers} threads...")

    alive_configs = []

    with ThreadPoolExecutor(max_workers=tcp_workers) as executor:
        results = executor.map(tcp_ping, configs)

        for is_alive, link, addr, port in results:
            if is_alive:
                alive_configs.append(link)

    print(f"[*] Alive servers: {len(alive_configs)}")

    if len(alive_configs) == 0:
        print("[!] No alive servers found.")
        exit()

    # ==========================================
    # Stage 2: Full Request Test
    # ==========================================
    print(f"\n[*] Starting full test on target: {target_name}")
    print(f"[*] Full test threads: {full_workers}")
    print("=" * 90)

    with ThreadPoolExecutor(max_workers=full_workers) as executor:
        futures = [
            executor.submit(
                process_request,
                link,
                req_spec,
                timeout,
                save_full_response,
                max_response_chars
            )
            for link in alive_configs
        ]

        for future in as_completed(futures):
            try:
                future.result()
            except:
                pass

    # ==========================================
    # Save Working Configs
    # ==========================================
    working_list.sort(key=lambda x: x[0])

    with open(WORKING_CONFIGS_FILE, "w", encoding="utf-8", errors="ignore") as f:
        f.write("Working configs sorted by speed / latency:\n")
        f.write("=" * 90 + "\n")

        for ping, status_code, response_len, link in working_list:
            f.write(f"[{ping}ms] [HTTP {status_code}] [{response_len} bytes] {link}\n")

    print("\n" + "=" * 90)
    print("✅ Testing complete!")
    print(f"🔹 Total working configs: {len(working_list)}")
    print(f"🔹 Detailed results saved in: {FULL_RESULTS_FILE}")
    print(f"🔹 Sorted config list saved in: {WORKING_CONFIGS_FILE}")

    if save_full_response:
        print(f"🔹 Individual full responses saved in: {RESPONSES_DIR}/")