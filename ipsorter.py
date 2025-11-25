import pandas as pd
import requests
from collections import defaultdict
import time
import os
import json
from datetime import datetime
import ipaddress

# Config
reports_dir = r'C:\SecReports\InputLogs'
output_dir = r'C:\SecReports\Compiled'
assets_dir = r'C:\SecReports\Assets'
cache_file = os.path.join(assets_dir, 'ip_cache.json')
preapproved_file = os.path.join(assets_dir, 'preapproved_ips.csv')
wazuh_config_file = os.path.join(assets_dir, 'wazuh_config.json')
API_DELAY_SECONDS = 1.2
GEO_API_URL = "http://ip-api.com/json/"
TRUST_STATUS_KEY = "trust_status"

os.makedirs(reports_dir, exist_ok=True)
os.makedirs(output_dir, exist_ok=True)
os.makedirs(assets_dir, exist_ok=True)

# Load cache
if os.path.isfile(cache_file):
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            ip_cache = json.load(f)
    except:
        ip_cache = {}
else:
    ip_cache = {}

# Load or create Wazuh config
def load_wazuh_config():
    if os.path.isfile(wazuh_config_file):
        try:
            with open(wazuh_config_file, 'r') as f:
                return json.load(f)
        except:
            pass
    return {
        "host": "172.27.22.250",
        "port": 55000,
        "username": "",
        "password": "",
        "verify_ssl": False
    }

def save_wazuh_config(config):
    try:
        with open(wazuh_config_file, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Failed to save Wazuh config: {e}")

def fetch_wazuh_office365_logs(config, days_back=7):
    """Fetch Office 365 UserLoggedIn events from Wazuh API"""
    import urllib3
    if not config.get('username') or not config.get('password'):
        print("Missing Wazuh credentials.")
        return None

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    base_url = f"https://{config['host']}:{config['port']}"
    auth_url = f"{base_url}/security/user/authenticate"

    try:
        auth_resp = requests.post(
            auth_url,
            json={"username": config['username'], "password": config['password']},
            verify=config['verify_ssl'],
            timeout=10
        )
    except Exception as e:
        print(f"Auth connection error: {e}")
        return None

    if auth_resp.status_code != 200:
        print(f"Auth failed ({auth_resp.status_code}): {auth_resp.text}")
        print("Check username/password, API port (55000), and user role permissions.")
        return None

    token = auth_resp.json().get('data', {}).get('token')
    if not token:
        print("Token missing in auth response.")
        return None

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # Time window
    end_time = datetime.utcnow()
    start_time = end_time - pd.Timedelta(days=days_back)

    # Wazuh events endpoint (Wazuh 4.x). Adjust 'q' if field names differ in your index.
    query_url = f"{base_url}/events"
    params = {
        'q': 'data.office365.Operation:UserLoggedIn',
        'date_from': start_time.strftime('%Y-%m-%d'),
        'date_to': end_time.strftime('%Y-%m-%d'),
        'limit': 10000
    }

    try:
        resp = requests.get(query_url, headers=headers, params=params,
                            verify=config['verify_ssl'], timeout=30)
    except Exception as e:
        print(f"Events request error: {e}")
        return None

    if resp.status_code == 401:
        print("401 Unauthorized when querying events. Possible causes:")
        print("- User lacks required role (needs at least READ permissions on events).")
        print("- Token expired (retry).")
        print("- Wrong endpoint (/events may differ in your Wazuh version).")
        return None
    if resp.status_code != 200:
        print(f"Events fetch failed ({resp.status_code}): {resp.text}")
        return None

    data = resp.json()
    events = data.get('data', {}).get('affected_items', [])
    if not events:
        print("No Office 365 login events found.")
        return None

    rows = []
    for event in events:
        o365 = event.get('data', {}).get('office365', {}) if isinstance(event.get('data', {}).get('office365', {}), dict) else {}
        rows.append({
            'timestamp': event.get('timestamp', ''),
            'data.office365.Subscription': o365.get('Subscription', ''),
            'data.office365.Operation': o365.get('Operation', ''),
            'data.office365.UserId': o365.get('UserId', ''),
            'data.office365.ClientIP': o365.get('ClientIP', ''),
            'rule.level': event.get('rule', {}).get('level', ''),
            'rule.id': event.get('rule', {}).get('id', '')
        })

    df = pd.DataFrame(rows)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    outfile = os.path.join(reports_dir, f'wazuh_office365_{ts}.csv')
    df.to_csv(outfile, index=False)
    print(f"Downloaded {len(df)} events to {outfile}")
    return outfile

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def load_preapproved(path: str):
    ips = set()
    networks = []
    if not os.path.isfile(path):
        print(f"Pre-approved list not found: {path}")
        return ips, networks
    try:
        dfw = pd.read_csv(path)
        if dfw.empty:
            return ips, networks
        cols_lower = {c.lower(): c for c in dfw.columns}
        col = cols_lower.get('ip', dfw.columns[0])
        for raw in dfw[col].dropna().astype(str).str.strip():
            if not raw:
                continue
            try:
                if '/' in raw:
                    networks.append(ipaddress.ip_network(raw, strict=False))
                else:
                    ipaddress.ip_address(raw)
                    ips.add(raw)
            except:
                continue
    except Exception as e:
        print(f"Failed to read pre-approved IPs: {e}")
    return ips, networks

def is_preapproved_ip(ip: str, approved_ips: set, approved_nets: list) -> bool:
    try:
        if ip in approved_ips:
            return True
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in approved_nets)
    except:
        return False

def fetch_geo(ip: str) -> dict:
    if is_private_ip(ip):
        return {
            "city": "Private",
            "region": "Private",
            "country": "Private",
            "location_full": "Private Network"
        }
    try:
        resp = requests.get(f"{GEO_API_URL}{ip}", timeout=5)
        data = resp.json()
        if data.get('status') == 'success':
            city = data.get('city', 'Unknown')
            region = data.get('regionName', 'Unknown')
            country = data.get('country', 'Unknown')
            return {
                "city": city or 'Unknown',
                "region": region or 'Unknown',
                "country": country or 'Unknown',
                "location_full": f"{city or 'Unknown'}, {region or 'Unknown'}, {country or 'Unknown'}"
            }
    except:
        pass
    return {
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "location_full": "Unknown"
    }

# Main menu
print("=== Office 365 Login Audit Tool ===\n")
print("1. Analyze existing CSV file")
print("2. Fetch logs from Wazuh XDR")
print("3. Configure Wazuh connection")

while True:
    try:
        mode = int(input("\nSelect option (1-3): "))
        if mode in [1, 2, 3]:
            break
        print("Invalid selection.")
    except ValueError:
        print("Enter a valid number.")

if mode == 3:
    # Configure Wazuh
    config = load_wazuh_config()
    print(f"\nCurrent Wazuh host: {config['host']}:{config['port']}")
    
    new_host = input(f"Wazuh host [{config['host']}]: ").strip() or config['host']
    new_port = input(f"Wazuh port [{config['port']}]: ").strip() or str(config['port'])
    new_user = input(f"Username [{config.get('username', '')}]: ").strip() or config.get('username', '')
    new_pass = input("Password (leave blank to keep current): ").strip()
    
    config['host'] = new_host
    config['port'] = int(new_port)
    config['username'] = new_user
    if new_pass:
        config['password'] = new_pass
    
    save_wazuh_config(config)
    print("Wazuh configuration saved.")
    exit()

if mode == 2:
    # Fetch from Wazuh
    config = load_wazuh_config()
    if not config.get('username') or not config.get('password'):
        print("Wazuh credentials not configured. Run option 3 first.")
        exit()
    
    days = input("How many days back to fetch? [7]: ").strip()
    days = int(days) if days else 7
    
    selected_file = fetch_wazuh_office365_logs(config, days)
    if not selected_file:
        print("Failed to fetch logs from Wazuh.")
        exit()
else:
    # List CSV files from InputLogs directory
    csv_files = [f for f in os.listdir(reports_dir) if f.lower().endswith('.csv')]
    if not csv_files:
        print(f"No CSV files found in {reports_dir}")
        exit()

    print("\n=== Available CSV Reports ===\n")
    for idx, filename in enumerate(csv_files, 1):
        print(f"{idx}. {filename}")

    while True:
        try:
            choice = int(input("\nEnter the number of the file to analyze: "))
            if 1 <= choice <= len(csv_files):
                selected_file = os.path.join(reports_dir, csv_files[choice - 1])
                break
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Enter a valid number.")

print(f"\nAnalyzing: {os.path.basename(selected_file)}\n")

# Load & filter
df = pd.read_csv(selected_file)
login_df = df[df['data.office365.Operation'] == 'UserLoggedIn'].copy()
if login_df.empty:
    print("No UserLoggedIn rows found.")
    exit()

login_df['IP_User'] = login_df['data.office365.ClientIP'] + "|" + login_df['data.office365.UserId']
ip_user_counts = login_df['IP_User'].value_counts()
unique_ips = sorted(set(login_df['data.office365.ClientIP'].dropna().tolist()))

# Build per-IP user counts for context
ip_user_detail = defaultdict(list)
tmp_group = login_df.groupby(['data.office365.ClientIP', 'data.office365.UserId']).size().reset_index(name='user_login_count')
for _, r in tmp_group.iterrows():
    ip_user_detail[r['data.office365.ClientIP']].append((r['data.office365.UserId'], r['user_login_count']))
# Sort user lists by count desc then user
for ip in ip_user_detail:
    ip_user_detail[ip].sort(key=lambda x: (-x[1], x[0]))

print("Resolving geolocation (cached where possible)...\n")
ip_geo = {}
for ip in unique_ips:
    cached_entry = ip_cache.get(ip)
    if cached_entry and all(k in cached_entry for k in ["city", "region", "country", "location_full"]):
        ip_geo[ip] = {
            "city": cached_entry["city"],
            "region": cached_entry["region"],
            "country": cached_entry["country"],
            "location_full": cached_entry["location_full"],
            TRUST_STATUS_KEY: cached_entry.get(TRUST_STATUS_KEY, "unknown")
        }
    else:
        geo = fetch_geo(ip)
        geo[TRUST_STATUS_KEY] = "unknown"
        ip_geo[ip] = geo
        if not is_private_ip(ip):
            time.sleep(API_DELAY_SECONDS)

approved_ips, approved_nets = load_preapproved(preapproved_file)
if approved_ips or approved_nets:
    print(f"Loaded pre-approved entries: {len(approved_ips)} IPs, {len(approved_nets)} networks")
for ip in unique_ips:
    if is_preapproved_ip(ip, approved_ips, approved_nets):
        ip_geo[ip][TRUST_STATUS_KEY] = "known"

print("\n=== Classify IPs (showing associated users) ===")
print("Pre-approved IPs skipped. K=Known, U=Untrusted, Enter=keep.")
for ip in unique_ips:
    # Skip if already known (pre-approved) or already untrusted
    if ip_geo[ip][TRUST_STATUS_KEY] in ["known", "untrusted"]:
        continue
    entry = ip_geo[ip]
    current = entry[TRUST_STATUS_KEY].capitalize()
    loc = entry['location_full']
    users_str = ", ".join(f"{u}({c})" for u, c in ip_user_detail.get(ip, []))
    print(f"\nIP: {ip}")
    print(f"Status: {current} | Location: {loc}")
    print(f"Users: {users_str if users_str else 'None'}")
    resp = input("Set (K/U/Enter): ").strip().lower()
    if resp == 'k':
        entry[TRUST_STATUS_KEY] = "known"
    elif resp == 'u':
        entry[TRUST_STATUS_KEY] = "untrusted"
    ip_geo[ip] = entry

for ip, entry in ip_geo.items():
    ip_cache[ip] = {
        "city": entry["city"],
        "region": entry["region"],
        "country": entry["country"],
        "location_full": entry["location_full"],
        TRUST_STATUS_KEY: entry[TRUST_STATUS_KEY]
    }

try:
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(ip_cache, f, indent=2)
    print(f"\nCache updated: {cache_file}")
except Exception as e:
    print(f"Failed to write cache: {e}")

location_data = defaultdict(list)
for _, row in login_df.iterrows():
    ip = row['data.office365.ClientIP']
    user = row['data.office365.UserId']
    key = f"{ip}|{user}"
    count = ip_user_counts[key]
    entry = ip_geo.get(ip, {})
    location_data[entry.get('location_full', 'Unknown')].append({
        'ip': ip,
        'user': user,
        'count': count,
        'trust_status': entry.get(TRUST_STATUS_KEY, 'unknown')
    })

print("\n=== User Logins by Location ===")
for location in sorted(location_data.keys()):
    print(f"\n{location}:")
    seen = set()
    # Sort: known first, then unknown, then untrusted
    sort_order = {'known': 0, 'unknown': 1, 'untrusted': 2}
    for item in sorted(location_data[location], key=lambda x: (sort_order.get(x['trust_status'], 3), x['user'])):
        k = (item['ip'], item['user'])
        if k not in seen:
            seen.add(k)
            status = item['trust_status'].capitalize()
            print(f"  {item['user']} from {item['ip']} (Count: {item['count']}, {status})")

export_rows = []
for combo, count in ip_user_counts.items():
    ip, user = combo.split('|', 1)
    meta = ip_geo.get(ip, {})
    export_rows.append({
        'user': user,
        'ip': ip,
        'count': count,
        'city': meta.get('city', 'Unknown'),
        'region': meta.get('region', 'Unknown'),
        'country': meta.get('country', 'Unknown'),
        'location_full': meta.get('location_full', 'Unknown'),
        'trust_status': meta.get(TRUST_STATUS_KEY, 'unknown').capitalize()
    })

export_df = pd.DataFrame(export_rows)
# Sort: Known, Unknown, Untrusted, then by country, then user
sort_order_map = {'Known': 0, 'Unknown': 1, 'Untrusted': 2}
export_df['sort_key'] = export_df['trust_status'].map(sort_order_map).fillna(3)
export_df.sort_values(by=['sort_key', 'country', 'user'], ascending=[True, True, True], inplace=True)
export_df.drop(columns=['sort_key'], inplace=True)

timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
out_file = os.path.join(output_dir, f'compiled_logins_{timestamp}.csv')
export_df.to_csv(out_file, index=False)

print(f"\nExport complete: {out_file}")
print(f"Rows exported: {len(export_df)}")
print("Summary:")
print(export_df['trust_status'].value_counts())

# --- Additional Script Section ---

# Read the CSV file
df = pd.read_csv(r'c:\Users\Edith\Downloads\events-2025-11-25T00_44_54.685Z.csv')

# Extract unique IPs (excluding empty and 'Not Available')
unique_ips = df['data.office365.ClientIP'].dropna().unique()
unique_ips = [ip for ip in unique_ips if ip and ip != 'Not Available']

# Dictionary to store IP geolocation data
ip_locations = defaultdict(list)

print("Fetching geolocation data for IPs...")

# Use a free IP geolocation API
for ip in unique_ips:
    try:
        # Using ip-api.com (free, no key required, but rate limited)
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                location = f"{data.get('city', 'Unknown')}, {data.get('regionName', 'Unknown')}, {data.get('country', 'Unknown')}"
                ip_locations[location].append({
                    'IP': ip,
                    'Country': data.get('country', 'Unknown'),
                    'Region': data.get('regionName', 'Unknown'),
                    'City': data.get('city', 'Unknown'),
                    'ISP': data.get('isp', 'Unknown'),
                    'Lat': data.get('lat', 'Unknown'),
                    'Lon': data.get('lon', 'Unknown')
                })
        time.sleep(1.5)  # Rate limiting
    except Exception as e:
        print(f"Error processing {ip}: {e}")

# Display results sorted by location
print("\n=== UNKNOWN IP LOGINS - ANALYZE FURTHER ===\n")
for location in sorted(ip_locations.keys()):
    print(f"\n{location}:")
    for ip_data in ip_locations[location]:
        print(f"  - {ip_data['IP']} ({ip_data['ISP']})")

# Save to CSV
result_data = []
for location, ips in ip_locations.items():
    for ip_data in ips:
        result_data.append(ip_data)

result_df = pd.DataFrame(result_data)
result_df.to_csv(r'c:\Users\Edith\Downloads\ips_by_location.csv', index=False)
print(f"\nResults saved to ips_by_location.csv")
input("Press enter to exit. . . ")