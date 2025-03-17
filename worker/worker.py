import feedparser
import sqlite3
import time
import os
import logging
from datetime import datetime, timedelta
import requests
from xml.etree import ElementTree as ET
import gzip
import io
import re
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def init_db():
    db_path = '/app/data/security_feeds.db'
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS feeds
                     (id INTEGER PRIMARY KEY, title TEXT, link TEXT UNIQUE, pub_date TEXT, source TEXT, category TEXT, advisory_number TEXT)''')
        c.execute("CREATE INDEX IF NOT EXISTS idx_pub_date ON feeds (pub_date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_source ON feeds (source)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_advisory_number ON feeds (advisory_number)")
        conn.commit()
        logging.info("Database initialized with indexes")
    except sqlite3.Error as e:
        logging.error(f"Database error in init_db: {e}")
        raise
    finally:
        conn.close()

def fetch_feeds():
    sources = {
        "SecurityWeek": ("https://www.securityweek.com/feed", "Vulnerabilities"),
        "The Hacker News": ("https://feeds.feedburner.com/TheHackersNews?format=xml", "Exploits"),
        "BleepingComputer": ("https://www.bleepingcomputer.com/feed/", "Exploits"),
        "Sophos Research": ("https://news.sophos.com/en-us/category/threat-research/feed/", "Advisories"),
        "Microsoft Security": ("https://api.msrc.microsoft.com/update-guide/rss", "Advisories"),
        "Red Hat Security": ("https://access.redhat.com/blogs/766093/feed", "Advisories"),
        "Dark Reading": ("https://www.darkreading.com/rss.xml", "Vulnerabilities"),
        "Krebs on Security": ("https://krebsonsecurity.com/feed/", "Exploits"),
        "CISA Alerts": ("https://www.cisa.gov/cybersecurity-advisories/all.xml", "Advisories"),
        "ZDI Upcoming": ("https://www.zerodayinitiative.com/rss/upcoming/", "Vulnerabilities"),
        "ZDI Published": ("https://www.zerodayinitiative.com/rss/published/", "Vulnerabilities"),
        "In the Wild Exploits": ("https://inthewild.io/feed", "Exploits"),
        "Ubuntu Security": ("https://ubuntu.com/security/notices/feed", "Advisories"),
        "Center for Internet Security": ("https://www.cisecurity.org/feed/advisories", "Advisories"),
        "Universal Cyberalerts.io Security Alerts": ("https://cyberalerts.io/rss/latest-public", "Advisories"),
    }
    nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-Recent.json.gz"

    db_path = '/app/data/security_feeds.db'
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        twenty_days_ago = datetime.now().astimezone() - timedelta(days=20)
        logging.info(f"Fetching feeds newer than {twenty_days_ago.isoformat()}")

        c.execute("DELETE FROM feeds WHERE pub_date < ?", (twenty_days_ago.isoformat(),))
        logging.info("Pruned entries older than 20 days.")

        for source, (url, category) in sources.items():
            try:
                if source == "Center for Internet Security":
                    response = requests.get(url, timeout=10)
                    response.raise_for_status()
                    html = response.text
                    advisory_pattern = r'https://www\.cisecurity\.org/advisory/[^"]+_2025-\d{3}'
                    advisory_urls = sorted(set(re.findall(advisory_pattern, html)), reverse=True)
                    entries = []
                    for advisory_url in advisory_urls[:10]:
                        advisory_num = advisory_url.split('_')[-1]
                        try:
                            resp = requests.get(advisory_url, timeout=10)
                            resp.raise_for_status()
                            root = ET.fromstring(resp.text) if '<html' in resp.text.lower() else None
                            title = root.findtext('.//title') if root else f"CIS Advisory {advisory_num}"
                        except Exception as e:
                            logging.warning(f"Failed to fetch {advisory_url}: {e}")
                            title = f"CIS Advisory {advisory_num}"
                        entries.append({
                            'title': title,
                            'link': advisory_url,
                            'published': datetime.now().isoformat(),
                            'advisory_number': advisory_num
                        })
                elif source == "In the Wild Exploits":
                    max_retries = 5
                    base_timeout = 90  # Increased to handle 30s response
                    entries = []
                    for attempt in range(max_retries):
                        try:
                            logging.info(f"Fetching JSON from {url} (Attempt {attempt + 1}/{max_retries})")
                            response = requests.get(url, timeout=base_timeout, verify=False)
                            response.raise_for_status()
                            elapsed = response.elapsed.total_seconds()
                            logging.info(f"Response status: {response.status_code}, length: {len(response.content)} bytes, time: {elapsed}s")
                            try:
                                exploits = response.json()
                                logging.info(f"Raw exploit count: {len(exploits)}")
                                if exploits:
                                    logging.debug(f"First few exploits: {json.dumps(exploits[:3], indent=2)}")
                                # Sort by timestamp, no cap for this source
                                exploits = sorted(exploits, key=lambda x: x.get('timeStamp', ''), reverse=True)
                                logging.info(f"Filtered to {len(exploits)} exploits")
                            except json.JSONDecodeError as e:
                                logging.error(f"JSON parsing failed: {e}. Raw content: {response.text[:1000]}")
                                exploits = []
                            for exploit in exploits:
                                pub_date_str = exploit.get('timeStamp', datetime.now().isoformat())
                                try:
                                    pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
                                except ValueError:
                                    logging.warning(f"Invalid timestamp in exploit {exploit.get('id', 'Unknown')}: {pub_date_str}")
                                    pub_date = datetime.now().astimezone()
                                # Add description snippet (max 100 chars)
                                desc = exploit.get('description', '')[:100]
                                entry = {
                                    'title': exploit.get('id', 'Untitled'),
                                    'link': exploit.get('referenceURL', f"{source}_no_link"),
                                    'published': pub_date.isoformat(),
                                    'description': desc if desc else None,
                                    'advisory_number': None
                                }
                                logging.debug(f"Processed exploit: {entry['title']} - {entry['published']}")
                                entries.append(entry)
                            break
                        except requests.Timeout as e:
                            logging.warning(f"Timeout after {base_timeout}s on attempt {attempt + 1}: {e}")
                            if attempt < max_retries - 1:
                                sleep_time = 2 ** attempt
                                logging.info(f"Retrying after {sleep_time}s...")
                                time.sleep(sleep_time)
                            else:
                                logging.error(f"All {max_retries} attempts timed out for {url}")
                                entries = []
                        except requests.RequestException as e:
                            logging.error(f"Network error fetching {url}: {e}")
                            entries = []
                            break
                else:
                    feed = feedparser.parse(url)
                    if feed.bozo:
                        logging.warning(f"Feedparser failed for {source}: {feed.bozo_exception}")
                        response = requests.get(url, timeout=10)
                        response.raise_for_status()
                        root = ET.fromstring(response.content)
                        entries = []
                        for item in root.findall('.//item'):
                            title = item.findtext('title', 'Untitled')
                            link = item.findtext('link', f"{source}_no_link")
                            pub_date_str = item.findtext('pubDate') or item.findtext('dc:date') or datetime.now().isoformat()
                            entries.append({'title': title, 'link': link, 'published': pub_date_str})
                    else:
                        entries = feed.entries

                if not entries:
                    logging.warning(f"No entries for {source}")
                    continue
                entries_added = 0
                limit = 10 if source != "In the Wild Exploits" else None  # No limit for In the Wild
                for entry in (entries[:limit] if limit else entries):
                    pub_date_str = entry.get('published') or entry.get('updated') or entry.get('pubDate') or datetime.now().isoformat()
                    try:
                        pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
                    except ValueError:
                        pub_date = datetime.now().astimezone()
                        logging.warning(f"Invalid date for {source}: {pub_date_str}")
                    if pub_date >= twenty_days_ago:
                        title = entry.get('title', 'Untitled')[:255]
                        link = entry.get('link', f"{source}_no_link_{entries_added}")
                        desc = entry.get('description', None) # Use description if present
                        advisory_num = entry.get('advisory_number', None)
                        c.execute("INSERT OR IGNORE INTO feeds (title, link, pub_date, source, category, description, advisory_number) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                  (title, link, pub_date.isoformat(), source, category, desc, advisory_num))
                        entries_added += 1
                logging.info(f"{source}: {len(entries)} total, {entries_added} added")
            except requests.RequestException as e:
                logging.error(f"Network error with {source}: {e}")
            except Exception as e:
                logging.error(f"Error with {source}: {e}")

        # NIST NVD JSON (unchanged)
        try:
            response = requests.get(nvd_url, timeout=15)
            response.raise_for_status()
            with gzip.GzipFile(fileobj=io.BytesIO(response.content)) as gz:
                nvd_data = json.load(gz)
            entries_added = 0
            for cve in nvd_data.get("CVE_Items", [])[:10]:
                pub_date_str = cve.get("publishedDate", datetime.now().isoformat())
                try:
                    pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
                except ValueError:
                    pub_date = datetime.now().astimezone()
                    logging.warning(f"Invalid NVD date: {pub_date_str}")
                if pub_date >= twenty_days_ago:
                    title = cve["cve"]["CVE_data_meta"]["ID"]
                    link = f"https://nvd.nist.gov/vuln/detail/{title}"
                    c.execute("INSERT OR IGNORE INTO feeds (title, link, pub_date, source, category, advisory_number) VALUES (?, ?, ?, ?, ?, ?)",
                              (title, link, pub_date.isoformat(), "NIST NVD", "Vulnerabilities", None))
                    entries_added += 1
            logging.info(f"NIST NVD: {len(nvd_data.get('CVE_Items', []))} total, {entries_added} added")
        except requests.RequestException as e:
            logging.error(f"NVD network error: {e}")
        except Exception as e:
            logging.error(f"NVD processing error: {e}")

        conn.commit()
        logging.info("Feed update completed.")
    except sqlite3.Error as e:
        logging.error(f"Database error in fetch_feeds: {e}")
        raise
    finally:
        conn.close()

if __name__ == "__main__":
    init_db()
    interval = int(os.getenv("FETCH_INTERVAL", 300))
    while True:
        try:
            fetch_feeds()
            logging.info(f"Sleeping for {interval} seconds")
            time.sleep(interval)
        except Exception as e:
            logging.error(f"Main loop error: {e}")
            time.sleep(60)
