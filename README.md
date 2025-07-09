# 🦊 Foxy - OSINT-based Sensitive Path & Secret Finder

**Foxy** is an automated OSINT (Open Source Intelligence) tool that collects historical and passive web data from multiple public sources. It identifies potentially sensitive paths, directories, backup files, and exposed keys or secrets. This makes it especially useful for reconnaissance during security assessments and bug bounty hunting.

## 🔍 What Foxy Finds
After collecting URLs from these sources, Foxy scans and filters for:

- 📁 Sensitive paths (e.g. `/admin`, `/internal`, `/config`, `/login`...)
- 📦 Backup or archive files (e.g. `.zip`, `.tar.gz`, `.bak`, `.old`...)
- 🔑 API keys, tokens, secrets, credentials in query strings or paths

## 🚀 Example Use Case
```bash
python3 foxy.py -d example.com
python3 foxy.py -w example.com
