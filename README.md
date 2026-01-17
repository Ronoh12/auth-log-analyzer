# 🔎 Auth Log Analyzer (Python)

## 📌 Overview
A lightweight **Blue Team / SOC-style** Python tool that analyzes Linux authentication logs and produces:
- Summary of **failed** and **successful** SSH logins
- Top offending **IP addresses**
- Top targeted **usernames**
- A timestamped **JSON report** for evidence and documentation

Works well on Ubuntu and WSL.

---

## 🔧 Tools Used
- Python 3 (stdlib only)
- Linux auth logs (`/var/log/auth.log`, `/var/log/secure`, or `/var/log/syslog`)
- Git & GitHub

---

## 📂 Project Structure
```text
auth-log-analyzer/
├── README.md
├── requirements.txt
├── reports/
│   └── auth_report_YYYY-MM-DD_HH-MM.json
└── src/
    └── analyze_auth_log.py

