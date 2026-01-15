# Python Web Application Firewall (WAF) Project

## Description
This project demonstrates a **simple Python WAF** built with Flask, acting as a **reverse proxy** to protect a backend web application from common web attacks such as SQL Injection (SQLi), Cross-Site Scripting (XSS), and brute-force attempts.  

It also includes a **simple backend web application** with login, signup, and admin/user pages, and a **log analysis tool** to study blocked and allowed requests.

---

## Features

- Reverse proxy WAF in Python using Flask
- Detection of malicious payloads:
  - SQL Injection (`OR 1=1`, `UNION SELECT`)
  - Cross-Site Scripting (`<script>` tags)
- Rate-limiting protection for sensitive endpoints (`/login`, `/signup`)
- Session-based authentication on the backend to protect `/admin` and `/user` pages
- JSON-based logging of all requests (blocked or allowed)
- Python log analysis tool to identify attack patterns and brute-force attempts

---

## Architecture
1. Client
2. WAF (Flask, port 5000)
   - Inspects payloads
   - Blocks malicious requests
   - Rate-limits sensitive endpoints
3. Backend App (Flask, port 5001)
   - Handles login, signup, admin/user pages
   - Enforces authentication and role-based access


