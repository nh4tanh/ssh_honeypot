
import json
from collections import defaultdict
from datetime import datetime, timedelta

DANGEROUS_COMMANDS = ['rm', 'wget', 'curl', 'nc', 'scp', 'bash', 'python', 'perl', 'nmap']

# Đọc auth.log
def detect_bruteforce(auth_log_path):
    attempts = defaultdict(list)
    with open(auth_log_path, 'r') as f:
        for line in f:
            if '[LOGIN ATTEMPT]' in line:
                try:
                    timestamp_str = line.split(']')[0].strip('[')
                    ip = line.split('LOGIN ATTEMPT]')[1].split()[0]
                    timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                    attempts[ip].append(timestamp)
                except:
                    continue

    brute_ips = []
    for ip, times in attempts.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if times[i] <= t <= times[i] + timedelta(seconds=60)]
            if len(window) >= 5:
                brute_ips.append((ip, len(window), times[i]))
                break  # chỉ cảnh báo một lần
    return brute_ips

# Đọc cmd_logs.json
def detect_dangerous_commands(cmd_log_path):
    danger_logs = []
    with open(cmd_log_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
                ip = entry['ip']
                cmd = entry['command']
                timestamp = entry['timestamp']
                if any(cmd.startswith(d) for d in DANGEROUS_COMMANDS):
                    danger_logs.append((timestamp, ip, cmd))
            except:
                continue
    return danger_logs

# In kết quả
def analyze_logs():
    print("\n[+] Brute-force Detection:")
    brute_results = detect_bruteforce('../log/auth.log')
    for ip, count, ts in brute_results:
        print(f"  - {ip} made {count} login attempts around {ts.strftime('%H:%M:%S')}")

    print("\n[+] Dangerous Commands:")
    danger_results = detect_dangerous_commands('../log/cmd_logs.json')
    for ts, ip, cmd in danger_results:
        print(f"  - {ts} | {ip} executed: {cmd}")

if __name__ == '__main__':
    analyze_logs()

