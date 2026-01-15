import json
from collections import Counter, defaultdict
from datetime import datetime

LOG_FILE = "waf_logs.json"

total_requests = 0
blocked_requests = 0
allowed_requests = 0

ip_counter = Counter()
path_counter = Counter()
reason_counter = Counter()

requests_per_ip = defaultdict(list)

with open(LOG_FILE, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:  # skip blank lines
            continue

        log = json.loads(line)

        total_requests += 1

        ip = log.get("ip")
        path = log.get("path")
        action = log.get("action")
        reason = log.get("reason")
        timestamp = log.get("timestamp")

        ip_counter[ip] += 1
        path_counter[path] += 1

        if action == "BLOCKED":
            blocked_requests += 1
            reason_counter[reason] += 1
        else:
            allowed_requests += 1

        # Track timestamps per IP (for brute-force detection)
        if timestamp:
            requests_per_ip[ip].append(
                datetime.fromisoformat(timestamp.replace("Z", ""))
            )


print("\n=== WAF LOG ANALYSIS REPORT ===\n")

print(f"Total requests: {total_requests}")
print(f"Blocked requests: {blocked_requests}")
print(f"Allowed requests: {allowed_requests}")

print("\n--- Top Attacking IPs ---")
for ip, count in ip_counter.most_common(5):
    print(f"{ip}: {count} requests")

print("\n--- Most Targeted Endpoints ---")
for path, count in path_counter.most_common(5):
    print(f"{path}: {count} hits")

print("\n--- Most Common Attack Reasons ---")
for reason, count in reason_counter.most_common():
    print(f"{reason}: {count}")

print("\n--- Possible Brute Force Detection ---")
for ip, times in requests_per_ip.items():
    times.sort()
    if len(times) >= 5:
        duration = (times[-1] - times[0]).seconds
        if duration <= 10:
            print(f"[!] {ip} made {len(times)} requests in {duration}s")
