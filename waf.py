# Acts as a reverse proxy and blocks malicious input before forwarding to backend
'''
1. Identify client IP
2. Rate limit / brute force check  
3. Extract payload
4. Detect XSS / SQLi
5. Forward to backend
6. Log everything
'''
from flask import Flask, request, Response
from collections import defaultdict
import time
import requests
import re
import logging
import json
import os
from datetime import datetime
from urllib.parse import unquote_plus

# =========================
# Rate limiting config
# =========================
RATE_LIMIT = 5       # requests
RATE_WINDOW = 60       # seconds
BLOCK_TIME = 300       # seconds
RATE_LIMIT_PATHS = {"/login", "/signup"}

ip_requests = defaultdict(list)
blocked_ips = {}

app = Flask(__name__)
BACKEND = "http://127.0.0.1:5001"

logging.basicConfig(level=logging.INFO)

LOG_FILE = "waf_logs.json"

BLOCK_PATTERNS = {
    "XSS": r"(?i)<\s*script",
    "SQLI_UNION": r"(?i)union\s+select",
    "SQLI_OR": r"(?i)or\s+1\s*=\s*1"
}

# =========================
# JSON logging helper
# =========================
def log_to_json(event):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def extract_payload(req):
    parts = []

    # ---- Query string ----
    if req.query_string:
        raw_qs = req.query_string.decode(errors="ignore")
        decoded_qs = unquote_plus(raw_qs)
        parts.append(raw_qs)
        parts.append(decoded_qs)

    # ---- Body ----
    raw_body = req.get_data(as_text=True)
    if raw_body:
        decoded_body = unquote_plus(raw_body)
        parts.append(raw_body)
        parts.append(decoded_body)

    # Remove duplicates
    return " | ".join(set(parts))



def detect_attack(payload):
    for name, pattern in BLOCK_PATTERNS.items():
        if re.search(pattern, payload):
            return name
    return None

def is_rate_limited(ip):
    now = time.time()

    # IP already blocked
    if ip in blocked_ips:
        if now < blocked_ips[ip]:
            return True
        else:
            del blocked_ips[ip]

    # Keep only recent requests
    ip_requests[ip] = [t for t in ip_requests[ip] if now - t < RATE_WINDOW]
    ip_requests[ip].append(now)

    if len(ip_requests[ip]) > RATE_LIMIT:
        blocked_ips[ip] = now + BLOCK_TIME
        return True

    return False


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def proxy(path):

    ip = request.remote_addr
    method = request.method

    # =========================
    # Rate limiting / brute force
    # =========================
    request_path = f"/{path}"

    if request_path in RATE_LIMIT_PATHS and is_rate_limited(ip):
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "ip": ip,
            "method": method,
            "path": request_path,
            "payload": None,
            "action": "BLOCKED",
            "reason": "RATE_LIMIT"
        }

        logging.warning(
            f"RATE_LIMIT | IP={ip} | Method={method} | Path={request_path}"
        )

        log_to_json(event)
        return Response("Too many requests", status=429)

    payload = extract_payload(request)
    attack = detect_attack(payload)
    event = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "ip": ip,
        "method": method,
        "path": f"/{path}",
        "payload": payload,
        "action": None,
        "reason": None
    }

    # =========================
    # Block malicious request
    # =========================
    if payload and attack:
        event["action"] = "BLOCKED"
        event["reason"] = attack

        logging.warning(
            f"BLOCKED | IP={ip} | Method={method} | Path=/{path} | Attack={attack}"
        )

        log_to_json(event)
        return Response("Blocked by WAF", status=403)

    # =========================
    # Allow clean request
    # =========================
    event["action"] = "ALLOWED"
    event["reason"] = "-"

    logging.info(
        f"ALLOWED | IP={ip} | Method={method} | Path=/{path}"
    )

    log_to_json(event)

    resp = requests.request(
        method=method,
        url=f"{BACKEND}/{path}",
        params=request.args,
        data=request.get_data(),
        headers={k: v for k, v in request.headers if k.lower() != "host"},
        allow_redirects=False
    )

    return Response(resp.content, resp.status_code, resp.headers.items())

if __name__ == "__main__":
    app.run(port=5000)
