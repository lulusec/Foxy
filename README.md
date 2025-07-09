# 🦊 Foxy - OSINT-based Sensitive Path & Secret Finder

**Foxy** is an automated OSINT (Open Source Intelligence) tool that collects historical and passive web data from multiple public sources. It identifies potentially sensitive paths, directories, backup files, and exposed keys or secrets. This makes it especially useful for reconnaissance during security assessments and bug bounty hunting.

## 🧠 What Foxy Looks For

Foxy scans collected URLs using pattern matching to detect potential risks. It focuses on three primary categories:

### 🗃️ Backup & Configuration Files

Foxy identifies exposed or historical files that may contain sensitive content, such as:

- `.bak`, `.sql`, `.zip`, `.rar`, `.7z`, `.tar.gz`, `.tgz`
- `.ddl`, `.iso`, `.jar`, `.old`, `.backup`
- `.config`, `.env`, `.env.local`, `.yml`, `.yaml`, `.json`
- `.log`, `.txt`, `.csv`, `.mdb`, `.db`, `.sqlite`

These files often contain source code, database dumps, or configuration details.

---

### 📁 Sensitive Paths and Directories

Foxy searches for URL paths that may lead to administrative panels, dev environments, or misconfigurations:

- `/admin`, `/dashboard`, `/login`, `/register`, `/api`
- `/config`, `/backup`, `/private`, `/uploads`, `/downloads`
- `/.git/`, `/.svn/`, `/.env`, `/docker-compose.yml`
- `/wp-admin`, `/phpmyadmin`

These paths are commonly overlooked and may expose internal functionality or sensitive resources.

---

### 🔑 Keys and Tokens in URLs

Foxy looks for secrets leaked directly in the query parameters of URLs:

- `?token=...`, `?key=...`, `?apikey=...`
- `?password=...`, `?secret=...`, `?auth=...`
- `?session=...`, `?access_token=...`, `?jwt=...`

Such values can be highly sensitive and may grant unauthorized access if not properly secured.

---

All matches are categorized and stored in the final report for easy analysis.

## 🚀 Example Use Case
```bash
# Investigate a single domain
python3 foxy.py -d example.com

# Investigate a subdomains (wildcard search)
python3 foxy.py -w example.com
