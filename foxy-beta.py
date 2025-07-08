import asyncio
import aiohttp
import json
import re
import argparse
import random
from urllib.parse import unquote
import os

# --- CONFIGURATION ---
# Place your VirusTotal API key here.
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE" 

# Terminal colors
class COLORS:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

# List of User-Agents to be used randomly
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
]

# URL templates
WAYBACK_URL = 'https://web.archive.org/cdx/search/cdx?url={DOMAIN}/*&output=json&fl=original&collapse=urlkey'
CCRAWL_INDEX_URL = 'http://index.commoncrawl.org/CC-MAIN-2023-50-index?url={DOMAIN}/*&output=json'
ALIENVAULT_URL = 'https://otx.alienvault.com/api/v1/indicators/domain/{DOMAIN}/url_list?limit=1000'
URLSCAN_URL = 'https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}&size=10000'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/domains/{DOMAIN}/urls?limit=40'

# --- PATTERNS FOR SEARCHING (REGULAR EXPRESSIONS) ---
PATTERNS = {
    "Backup Files": re.compile(r'\.(bak|sql|zip|rar|7z|tar\.gz|tgz|ddl|iso|jar|old|backup|config|yml|yaml|json|log|txt|csv|mdb|db|sqlite|env(\.local)?)$', re.IGNORECASE),
    "Sensitive Paths and Directories": re.compile(r'/(admin|dashboard|login|register|api|config|backup|private|uploads|downloads|\.git|\.svn|\.env|docker-compose\.yml|wp-admin|phpmyadmin)/', re.IGNORECASE),
    "Keys and Tokens in URL": re.compile(r'[\?&](token|key|apikey|password|secret|auth|session|access_token|jwt)=[^&]+', re.IGNORECASE)
}

# <<< ZMENA: Pridaný regulárny výraz na vylúčenie súborov
EXCLUSION_PATTERN = re.compile(
    r'\.(css|js|jpe?g|png|svg|gif|scss|tif|tiff|otf|woff|woff2|webp|flv|ogv|jpeg|jpg|ico|img)(\?.*)?$', 
    re.IGNORECASE
)


async def fetch_urls(session, url, source_name):
    """Asynchronously fetches and processes URLs from a single source."""
    print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Scanning {source_name}...")
    urls = set()
    try:
        headers = {
            'User-Agent': random.choice(USER_AGENTS)
        }
        
        if source_name == "VirusTotal":
            if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
                print(f"{COLORS.YELLOW}[WARNING]{COLORS.ENDC} VirusTotal API key is missing. Skipping this source.")
                return set()
            headers['x-apikey'] = VIRUSTOTAL_API_KEY
        
        async with session.get(url, headers=headers, timeout=30) as response:
            if response.status == 200:
                if source_name in ["Wayback Machine", "Common Crawl"]:
                    text_content = await response.text()
                    if source_name == "Wayback Machine":
                        try:
                            data = json.loads(text_content)
                            for item in data[1:]: urls.add(unquote(item[0]))
                        except json.JSONDecodeError:
                             print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} {source_name} returned an unexpected format.")
                    else: # Common Crawl
                        for line in text_content.strip().split('\n'):
                            try: urls.add(unquote(json.loads(line).get('url')))
                            except (json.JSONDecodeError, AttributeError): continue
                elif source_name == "AlienVault":
                    data = await response.json()
                    for item in data.get('url_list', []): urls.add(unquote(item.get('url')))
                elif source_name == "URLScan":
                    data = await response.json()
                    for result in data.get('results', []):
                        urls.add(unquote(result.get('page', {}).get('url')))
                        urls.add(unquote(result.get('task', {}).get('url')))
                elif source_name == "VirusTotal":
                    data = await response.json()
                    for item in data.get('data', []): urls.add(unquote(item.get('attributes', {}).get('url')))
                
                print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} {source_name} found {len(urls)} unique URLs.")
                return urls
            else:
                print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} {source_name} returned status {response.status}: {await response.text()}")
                return set()
    except asyncio.TimeoutError:
        print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} Timeout occurred for {source_name}.")
        return set()
    except aiohttp.ClientError as e:
        print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} Connection issue with {source_name}: {e}")
        return set()

def analyze_urls(urls_to_analyze): # <<< ZMENA: Premenovaná premenná pre jasnosť
    """Analyzes a list of URLs for defined patterns."""
    # <<< ZMENA: Hláška sa teraz vypisuje v main, tu sa len analyzuje
    findings = {key: set() for key in PATTERNS.keys()}
    for url in urls_to_analyze:
        if not url: continue
        decoded_url = unquote(url)
        for category, pattern in PATTERNS.items():
            if pattern.search(decoded_url):
                findings[category].add(decoded_url)
    return findings

def generate_report(domain, findings, total_urls_analyzed): # <<< ZMENA: Premenovaná premenná
    """Generates a summary to the console and a detailed report to a file."""
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    report_filename = os.path.join(output_dir, f"report-{domain}.txt")
    
    # --- Časť pre výpis do terminálu (iba súhrn) ---
    print("\n" + "="*50)
    print(f" SUMMARY REPORT FOR DOMAIN: {domain}")
    print("="*50)
    # <<< ZMENA: Upravený text pre jasnosť
    print(f"Total unique URLs analyzed (after filtering): {total_urls_analyzed}\n")
    
    has_findings = False
    for category, urls in findings.items():
        count = len(urls)
        if count > 0:
            print(f"  {COLORS.GREEN}[+] {category}: {count} findings{COLORS.ENDC}")
            has_findings = True
        else:
            print(f"  [-] {category}: 0 findings")
    
    if not has_findings:
        print(f"\n{COLORS.GREEN}No sensitive information found based on the defined patterns.{COLORS.ENDC}")

    print("\n" + "="*50)
    print(f" DETAILED REPORT (saving to {report_filename})")
    print("="*50)

    # --- Časť pre zápis do súboru (detailný report) ---
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(f"FINAL REPORT FOR DOMAIN: {domain}\n")
        f.write(f"Total unique URLs analyzed (after filtering): {total_urls_analyzed}\n\n")

        if not has_findings:
            f.write("No sensitive information found based on the defined patterns.\n")
        else:
            for category, urls in findings.items():
                if urls:
                    title = f"--- FINDINGS: {category} ({len(urls)}) ---"
                    f.write(f"{title}\n")
                    for url in sorted(list(urls)):
                        f.write(f"  [+] {url}\n")
                    f.write("\n")

    print(f"\n{COLORS.BLUE}[INFO]{COLORS.ENDC} Full report has been saved to file: {report_filename}")

async def main(domain):
    """The main function that orchestrates the entire process."""
    async with aiohttp.ClientSession() as session:
        tasks = [
            fetch_urls(session, WAYBACK_URL.format(DOMAIN=domain), "Wayback Machine"),
            fetch_urls(session, CCRAWL_INDEX_URL.format(DOMAIN=domain), "Common Crawl"),
            fetch_urls(session, ALIENVAULT_URL.format(DOMAIN=domain), "AlienVault"),
            fetch_urls(session, URLSCAN_URL.format(DOMAIN=domain), "URLScan"),
            fetch_urls(session, VIRUSTOTAL_URL.format(DOMAIN=domain), "VirusTotal"),
        ]
        results = await asyncio.gather(*tasks)
        
        all_urls = set().union(*[s for s in results if s])
        
        if not all_urls:
            print(f"\n{COLORS.RED}[ERROR]{COLORS.ENDC} Failed to fetch any URLs. The script is terminating.")
            return

        # <<< ZMENA: Blok kódu pre filtrovanie URL adries
        initial_count = len(all_urls)
        print(f"\n{COLORS.BLUE}[INFO]{COLORS.ENDC} Collected {initial_count} total unique URLs.")
        
        # Aplikujeme filter a vytvoríme nový set s prefiltrovanými URL
        filtered_urls = {url for url in all_urls if url and not EXCLUSION_PATTERN.search(url)}
        
        excluded_count = initial_count - len(filtered_urls)
        print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Filtering out common asset files... Excluded {excluded_count} URLs.")
        
        print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Analyzing {len(filtered_urls)} remaining URLs...")
        # Koniec bloku zmeny

        # <<< ZMENA: Do analýzy a reportu posielame prefiltrované dáta
        findings = analyze_urls(filtered_urls)
        generate_report(domain, findings, len(filtered_urls))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A tool to find sensitive files and information from online sources.")
    parser.add_argument("domain", help="The domain to investigate (e.g., example.com)")
    args = parser.parse_args()
    
    asyncio.run(main(args.domain))
