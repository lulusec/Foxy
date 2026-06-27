import asyncio
import aiohttp
import json
import re
import argparse
import random
from urllib.parse import unquote, quote
import os

# Terminal colors
class COLORS:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    ENDC = '\033[0m'

# List of User-Agents to be used randomly
USER_AGENTS = [
    # Chrome - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    # Chrome - Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    # Chrome - Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 8172.45.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.64 Safari/537.36",
    # Firefox - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:67.0) Gecko/20100101 Firefox/67.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
    # Firefox - Mac & Linux
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.1; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    # Safari - Mac & iOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 7_1_2 like Mac OS X) AppleWebKit/537.51.2 (KHTML, like Gecko) Version/7.0 Mobile/11D257 Safari/9537.53",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 8_4_1 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12H321 Safari/600.1.4",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.2088.76",
    # Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    # IE / legacy
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)",
]

# Wayback Machine
WAYBACK_DOMAIN_URL = 'https://web.archive.org/cdx/search/cdx?url={DOMAIN}/*&output=json&fl=original&collapse=urlkey&limit=50000'
WAYBACK_WILDCARD_URL = 'https://web.archive.org/cdx/search/cdx?url=*.{DOMAIN}/*&output=json&fl=original&collapse=urlkey&limit=50000'

# Common Crawl - viacero indexov (rozne roky = viac dat)
CCRAWL_2024_URL = 'http://index.commoncrawl.org/CC-MAIN-2024-22-index?url={DOMAIN}/*&output=json'
CCRAWL_2023_URL = 'http://index.commoncrawl.org/CC-MAIN-2023-50-index?url={DOMAIN}/*&output=json'
CCRAWL_2022_URL = 'http://index.commoncrawl.org/CC-MAIN-2022-49-index?url={DOMAIN}/*&output=json'

# Ostatne zdroje
ALIENVAULT_URL = 'https://otx.alienvault.com/api/v1/indicators/domain/{DOMAIN}/url_list?limit=1000'
URLSCAN_URL = 'https://urlscan.io/api/v1/search/?q=domain:{DOMAIN}&size=10000'

# Nove zdroje
THREATMINER_URL = 'https://api.threatminer.org/v2/domain.php?q={DOMAIN}&rt=5'
URLHAUS_URL = 'https://urlhaus-api.abuse.ch/v1/host/'
VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/domains/{DOMAIN}/urls?limit=40'

# --- PATTERNS FOR SEARCHING (REGULAR EXPRESSIONS) ---
PATTERNS = {
    "Backup Files": re.compile(r'\.(bak|sql|zip|rar|7z|tar\.gz|tgz|ddl|iso|jar|old|backup|config|yml|yaml|json|log|txt|csv|mdb|db|sqlite|env(\.local)?)$', re.IGNORECASE),
    "Sensitive Paths and Directories": re.compile(r'/(admin|dashboard|login|register|api|config|backup|private|uploads|downloads|\.git|\.svn|\.env|docker-compose\.yml|wp-admin|phpmyadmin)/', re.IGNORECASE),
    "Keys and Tokens in URL": re.compile(r'[\?&](token|key|apikey|password|secret|auth|session|access_token|jwt)=[^&]+', re.IGNORECASE)
}

# Regulárny výraz na vylúčenie bežných súborov
EXCLUSION_PATTERN = re.compile(
    r'\.(css|js|jpe?g|png|svg|gif|webp|scss|tif|tiff|otf|woff|woff2|flv|ogv|ico|img)(\?.*)?$', 
    re.IGNORECASE
)


async def fetch_wayback_deep(session, base_url):
    """Paginated fetch - prechodzi vsetky stranky Wayback Machine bez limitu."""
    print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Scanning Wayback Machine [DEEP - vsetky stranky]...")
    urls = set()
    page = 0
    resume_key = None
    PAGE_SIZE = 10000

    # Odstran existujuci limit a pridaj strankovanie
    clean_url = base_url.split('&limit=')[0]
    paginated_url = clean_url + f"&showResumeKey=true&limit={PAGE_SIZE}"

    while True:
        page += 1
        current_url = paginated_url
        if resume_key:
            current_url += f"&resumeKey={quote(resume_key, safe='')}"

        for attempt in range(1, 4):
            try:
                timeout = aiohttp.ClientTimeout(total=120)
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                async with session.get(current_url, headers=headers, timeout=timeout, ssl=False) as response:
                    if response.status == 200:
                        text = await response.text()
                        try:
                            data = json.loads(text)
                        except json.JSONDecodeError:
                            print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} Wayback Machine: nespravny format na strane {page}.")
                            return urls

                        if len(data) <= 1:
                            print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Wayback Machine: dokoncene ({page} stran, {len(urls)} URL).")
                            return urls

                        rows = data[1:]  # Preskoc hlavicku ["original"]

                        # Zistenie resumeKey: posledny riadok ktory nevyzera ako URL
                        last_val = rows[-1][0] if rows and rows[-1] else ""
                        if last_val and not last_val.startswith(('http://', 'https://', 'ftp://')):
                            resume_key = last_val
                            rows = rows[:-1]
                        else:
                            resume_key = None

                        count_before = len(urls)
                        for item in rows:
                            if item and item[0]:
                                urls.add(unquote(item[0]))

                        new_added = len(urls) - count_before
                        print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Wayback Machine: strana {page} → +{new_added} URL ({len(urls)} celkom)")

                        if not resume_key:
                            print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Wayback Machine: vsetky stranky hotove. Celkom: {len(urls)} URL.")
                            return urls
                        break  # Uspech, dalsia strana

                    elif response.status == 429:
                        wait = 10 * attempt
                        print(f"{COLORS.YELLOW}[WARN]{COLORS.ENDC} Wayback Machine rate limit. Cakam {wait}s...")
                        await asyncio.sleep(wait)
                    else:
                        print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} Wayback Machine status {response.status} na strane {page}.")
                        return urls

            except asyncio.TimeoutError:
                print(f"{COLORS.YELLOW}[WARN]{COLORS.ENDC} Wayback Machine timeout na strane {page}. Pokus {attempt}/3...")
                await asyncio.sleep(5 * attempt)
            except aiohttp.ClientError as e:
                print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} Wayback Machine chyba spojenia: {e}")
                return urls

        await asyncio.sleep(1)  # Kratka pauza medzi stranami

    return urls


async def fetch_urls(session, url, source_name, retry=3, post_data=None, extra_headers=None):
    """Asynchronously fetches and processes URLs from a single source."""
    print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Scanning {source_name}...")
    urls = set()
    for attempt in range(1, retry + 1):
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            if extra_headers:
                headers.update(extra_headers)

            if source_name == "Wayback Machine":
                timeout = aiohttp.ClientTimeout(total=120)
            elif source_name.startswith("Common Crawl"):
                timeout = aiohttp.ClientTimeout(total=90)
            else:
                timeout = aiohttp.ClientTimeout(total=60)

            request_method = session.post if post_data else session.get
            request_kwargs = {'headers': headers, 'timeout': timeout, 'ssl': False}
            if post_data:
                request_kwargs['data'] = post_data

            async with request_method(url, **request_kwargs) as response:
                if response.status == 200:
                    if source_name == "Wayback Machine" or source_name.startswith("Common Crawl"):
                        text_content = await response.text()
                        if source_name == "Wayback Machine":
                            try:
                                data = json.loads(text_content)
                                for item in data[1:]: urls.add(unquote(item[0]))
                            except json.JSONDecodeError:
                                print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} {source_name} returned an unexpected format.")
                        else:  # Common Crawl (akykolvek rok)
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
                    elif source_name == "ThreatMiner":
                        data = await response.json(content_type=None)
                        for u in data.get('results', []):
                            if u: urls.add(unquote(u))
                    elif source_name == "URLhaus":
                        data = await response.json(content_type=None)
                        for item in data.get('urls', []):
                            u = item.get('url')
                            if u: urls.add(unquote(u))
                    elif source_name == "VirusTotal":
                        data = await response.json()
                        for item in data.get('data', []):
                            u = item.get('attributes', {}).get('url')
                            if u: urls.add(unquote(u))

                    print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} {source_name} found {len(urls)} unique URLs.")
                    return urls
                elif response.status == 429:
                    wait_time = 5 * attempt
                    print(f"{COLORS.YELLOW}[WARN]{COLORS.ENDC} {source_name} rate limited (429). Waiting {wait_time}s before retry {attempt}/{retry}...")
                    await asyncio.sleep(wait_time)
                elif response.status in (504, 502, 503):
                    print(f"{COLORS.YELLOW}[WARN]{COLORS.ENDC} {source_name} server error ({response.status}). Retry {attempt}/{retry}...")
                    await asyncio.sleep(3 * attempt)
                elif response.status == 404:
                    print(f"{COLORS.YELLOW}[WARN]{COLORS.ENDC} {source_name} - domena nenajdena v tomto zdroji.")
                    return set()
                else:
                    print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} {source_name} returned status {response.status}.")
                    return set()
        except asyncio.TimeoutError:
            print(f"{COLORS.YELLOW}[WARN]{COLORS.ENDC} Timeout for {source_name}. Retry {attempt}/{retry}...")
            await asyncio.sleep(3)
        except aiohttp.ClientError as e:
            print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} Connection issue with {source_name}: {e}")
            return set()

    print(f"{COLORS.RED}[ERROR]{COLORS.ENDC} {source_name} failed after {retry} attempts. Skipping.")
    return set()

def analyze_urls(urls_to_analyze):
    """Analyzes a list of URLs for defined patterns."""
    findings = {key: set() for key in PATTERNS.keys()}
    for url in urls_to_analyze:
        if not url: continue
        decoded_url = unquote(url)
        for category, pattern in PATTERNS.items():
            if pattern.search(decoded_url):
                findings[category].add(decoded_url)
    return findings

def generate_report(domain, findings, total_urls_analyzed):
    """Generates a summary to the console and a detailed report to a file."""
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    
    report_filename = os.path.join(output_dir, f"report-{domain}.txt")
    
    print("\n" + "="*50)
    print(f" SUMMARY REPORT FOR DOMAIN: {domain}")
    print("="*50)
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

async def main(domain, is_wildcard, vt_key=None):
    """The main function that orchestrates the entire process."""

    if is_wildcard:
        wayback_url = WAYBACK_WILDCARD_URL.format(DOMAIN=domain)
        print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Wildcard search enabled for Wayback Machine (*.{domain})")
    else:
        wayback_url = WAYBACK_DOMAIN_URL.format(DOMAIN=domain)

    if vt_key:
        print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} VirusTotal API klic detekovany - bude pouzity.")
    else:
        print(f"{COLORS.YELLOW}[WARN]{COLORS.ENDC} VirusTotal preskoceny (nebol zadany --vt API_KEY).")

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            fetch_urls(session, wayback_url, "Wayback Machine"),
            fetch_urls(session, CCRAWL_2024_URL.format(DOMAIN=domain), "Common Crawl (2024)"),
            fetch_urls(session, CCRAWL_2023_URL.format(DOMAIN=domain), "Common Crawl (2023)"),
            fetch_urls(session, CCRAWL_2022_URL.format(DOMAIN=domain), "Common Crawl (2022)"),
            fetch_urls(session, ALIENVAULT_URL.format(DOMAIN=domain), "AlienVault"),
            fetch_urls(session, URLSCAN_URL.format(DOMAIN=domain), "URLScan"),
            fetch_urls(session, THREATMINER_URL.format(DOMAIN=domain), "ThreatMiner"),
            fetch_urls(session, URLHAUS_URL, "URLhaus", post_data={'host': domain}),
        ]
        if vt_key:
            tasks.append(fetch_urls(
                session, VIRUSTOTAL_URL.format(DOMAIN=domain), "VirusTotal",
                extra_headers={'x-apikey': vt_key}
            ))

        results = await asyncio.gather(*tasks)
        
        all_urls = set().union(*[s for s in results if s])
        
        if not all_urls:
            print(f"\n{COLORS.RED}[ERROR]{COLORS.ENDC} Failed to fetch any URLs. The script is terminating.")
            return

        initial_count = len(all_urls)
        print(f"\n{COLORS.BLUE}[INFO]{COLORS.ENDC} Collected {initial_count} total unique URLs.")
        
        filtered_urls = {url for url in all_urls if url and not EXCLUSION_PATTERN.search(url)}
        
        excluded_count = initial_count - len(filtered_urls)
        print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Filtering out common asset files... Excluded {excluded_count} URLs.")
        
        print(f"{COLORS.BLUE}[INFO]{COLORS.ENDC} Analyzing {len(filtered_urls)} remaining URLs...")

        findings = analyze_urls(filtered_urls)
        generate_report(domain, findings, len(filtered_urls))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A tool to find sensitive files and information from online sources.")
    
    # <<< ZMENA: Vytvorenie vzájomne sa vylučujúcej skupiny argumentov
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="The domain to investigate (e.g., example.com)")
    group.add_argument("-w", "--wildcard", help="The domain to investigate with subdomains (e.g., example.com for *.example.com search)")
    
    parser.add_argument("--vt", dest="vt_key", metavar="API_KEY",
                        help="Volitelny VirusTotal API klic (zdarma na virustotal.com)")

    args = parser.parse_args()

    if args.domain:
        target_domain = args.domain
        is_wildcard_search = False
    else:
        target_domain = args.wildcard
        is_wildcard_search = True

    asyncio.run(main(target_domain, is_wildcard_search, vt_key=args.vt_key))
