# 🦊 Foxy - OSINT-based Sensitive Path & Secret Finder
**Foxy** is an automated OSINT (Open Source Intelligence) tool that collects historical and passive web data from multiple public sources. It identifies potentially sensitive paths, directories, backup files, and exposed keys or secrets. This makes it especially useful for reconnaissance during security assessments and bug bounty hunting.


## 🚀 Example Use Case
```
# Investigate a single domain
python foxy.py -d example.com

# Investigate a subdomains (wildcard search)
python foxy.py -w example.com
```

## 🧠 What Foxy Looks For
Foxy scans collected URLs using pattern matching to detect potential risks. It focuses on three primary categories:
### 🗃️ Backup & Configuration Files
- `.bak`, `.sql`, `.zip`, `.rar`, `.7z`, `.tar.gz`, `.tgz`
- `.ddl`, `.iso`, `.jar`, `.old`, `.backup`
- `.config`, `.env`, `.env.local`, `.yml`, `.yaml`, `.json`
- `.log`, `.txt`, `.csv`, `.mdb`, `.db`, `.sqlite`
---

### 📁 Sensitive Paths and Directories
- `/admin`, `/dashboard`, `/login`, `/register`, `/api`
- `/config`, `/backup`, `/private`, `/uploads`, `/downloads`
- `/.git/`, `/.svn/`, `/.env`, `/docker-compose.yml`
- `/wp-admin`, `/phpmyadmin`, 
---

### 🔑 Keys and Tokens in URLs
- `?token=...`, `?key=...`, `?apikey=...`
- `?password=...`, `?secret=...`, `?auth=...`
- `?session=...`, `?access_token=...`, `?jwt=...`
---
