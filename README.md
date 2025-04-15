# 🔍 VirusTotal Checker

This is a simple Python script that checks whether a given IP address, domain, URL, or file hash is flagged as malicious using the [VirusTotal API](https://www.virustotal.com/gui/home/search).

## ✅ Features

- Supports IPs, Domains, URLs, and Hashes
- Uses VirusTotal API v3
- Simple CLI interface
- Returns: `Malicious` or `Clean`

## 📦 Requirements

- Python 3.x
- `requests` library

Install dependencies:
```bash
pip install requests
```
## 🛠 Usage
```bash
python vt_checker.py <value>
```
Examples:
```bash
python vt_checker.py 8.8.8.8
python vt_checker.py example.com
python vt_checker.py https://example.com
python vt_checker.py d41d8cd98f00b204e9800998ecf8427e
```
🔐 API Key
You need a free VirusTotal API key. Sign up at virustotal.com, then add your API key in the script:
```py
API_KEY = 'YOUR_API_KEY_HERE'
```
