# 🦊 Foxy - OSINT-based Sensitive Path & Secret Finder
**Foxy** is an automated OSINT (Open Source Intelligence) tool that collects historical and passive web data from multiple public sources. It identifies potentially sensitive paths, directories, backup files, and exposed keys or secrets. This makes it especially useful for reconnaissance during security assessments and bug bounty hunting.

<p align="center">
 <img src="https://github.com/user-attachments/assets/0392e8f9-00ff-466d-87de-3b82bda2c439" alt="image">
</p>


## 🚀 Example Use Case
#### Investigate a single domain
```
python foxy.py -d example.com
```
#### Investigate a subdomains (wildcard search)
```
python foxy.py -w example.com
```

#### with VirusTotal apikey
```
python foxy.py -d example.com --vt TVOJ_API_KLUC
python foxy.py -w example.com --vt TVOJ_API_KLUC
```

## 🧠 What Foxy Looks For
Foxy scans collected URLs using pattern matching to detect potential risks. It focuses on three primary categories:
  - #### 🗃️ Backup & Configuration Files
  - #### 📁 Sensitive Paths and Directories
  - #### 🔑 Keys and Tokens in URLs
