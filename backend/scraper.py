import httpx
import json
import os
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict

CACHE_FILE = os.environ.get("CACHE_FILE", "q_intel_cache.json")
CACHE_TTL_HOURS = 24


class DataScraper:

    def _load_cache(self) -> Dict:
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE) as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_cache(self, cache: Dict):
        try:
            with open(CACHE_FILE, "w") as f:
                json.dump(cache, f)
        except Exception as e:
            print(f"[scraper] Cache save error: {e}")

    def _is_fresh(self, cache: Dict, key: str) -> bool:
        entry = cache.get(key, {})
        fetched_at = entry.get("fetched_at")
        if not fetched_at:
            return False
        age = datetime.utcnow() - datetime.fromisoformat(fetched_at)
        return age < timedelta(hours=CACHE_TTL_HOURS)

    def get_cache_info(self) -> Dict:
        cache = self._load_cache()
        return {
            key: {
                "fetched_at": val.get("fetched_at"),
                "count": len(val.get("data", [])),
                "fresh": self._is_fresh(cache, key),
            }
            for key, val in cache.items()
        }

    async def fetch_nvd(self, keyword: str) -> List[Dict]:
        """Fetch CVEs from NVD NIST API for a keyword with 24h file cache."""
        cache = self._load_cache()
        cache_key = f"nvd_{keyword}"
        if self._is_fresh(cache, cache_key):
            print(f"[scraper] Cache hit: NVD '{keyword}' ({len(cache[cache_key]['data'])} CVEs)")
            return cache[cache_key]["data"]

        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {}
        api_key = os.environ.get("NVD_API_KEY")
        if api_key:
            headers["apiKey"] = api_key

        params = {"keywordSearch": keyword, "resultsPerPage": 50}
        try:
            async with httpx.AsyncClient(timeout=30, headers=headers) as client:
                r = await client.get(url, params=params)
                r.raise_for_status()
                data = r.json()
                cves = []
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    descs = cve.get("descriptions", [])
                    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

                    # Extract CVSS severity and score (prefer v3.1 > v3.0 > v2)
                    metrics = cve.get("metrics", {})
                    severity = "UNKNOWN"
                    cvss_score = 0.0
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        metric_list = metrics.get(version, [])
                        if metric_list:
                            cvss_data = metric_list[0].get("cvssData", {})
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            cvss_score = cvss_data.get("baseScore", 0.0)
                            break

                    # Extract affected vendor:product pairs from CPE data
                    affected_products = []
                    for config in cve.get("configurations", []):
                        for node in config.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                cpe = match.get("criteria", "")
                                parts = cpe.split(":")
                                if len(parts) > 4 and parts[3] != "*" and parts[4] != "*":
                                    affected_products.append(f"{parts[3]}:{parts[4]}")

                    cves.append({
                        "id": cve.get("id"),
                        "title": cve.get("id"),
                        "description": desc,
                        "severity": severity,
                        "cvss_score": cvss_score,
                        "published": cve.get("published", ""),
                        "modified": cve.get("lastModified", ""),
                        "affected_products": list(set(affected_products))[:5],
                        "keyword": keyword,
                    })

                cache[cache_key] = {"data": cves, "fetched_at": datetime.utcnow().isoformat()}
                self._save_cache(cache)
                print(f"[scraper] Fetched {len(cves)} CVEs for '{keyword}' from NVD")
                return cves
        except Exception as e:
            print(f"[scraper] NVD error ('{keyword}'): {e}")
            return cache.get(cache_key, {}).get("data", [])

    async def fetch_cisa_kev(self) -> List[Dict]:
        """Fetch CISA KEV filtered by quantum/cryptography keywords, with 24h file cache."""
        cache = self._load_cache()
        cache_key = "cisa_kev"
        if self._is_fresh(cache, cache_key):
            print(f"[scraper] Cache hit: CISA KEV ({len(cache[cache_key]['data'])} entries)")
            return cache[cache_key]["data"]

        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        filter_kws = ["quantum", "cryptograph"]

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(url)
                r.raise_for_status()
                all_vulns = r.json().get("vulnerabilities", [])
                filtered = []
                for v in all_vulns:
                    text = " ".join([
                        v.get("vulnerabilityName", ""),
                        v.get("shortDescription", ""),
                        v.get("product", ""),
                        v.get("vendorProject", ""),
                    ]).lower()
                    if any(kw in text for kw in filter_kws):
                        filtered.append({
                            "id": v.get("cveID"),
                            "name": v.get("vulnerabilityName", ""),
                            "description": v.get("shortDescription", ""),
                            "vendor": v.get("vendorProject", ""),
                            "product": v.get("product", ""),
                            "date_added": v.get("dateAdded", ""),
                            "due_date": v.get("dueDate", ""),
                            "required_action": v.get("requiredAction", ""),
                            "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                            "source": "CISA_KEV",
                        })
                cache[cache_key] = {"data": filtered, "fetched_at": datetime.utcnow().isoformat()}
                self._save_cache(cache)
                print(f"[scraper] Fetched {len(filtered)} KEV quantum/crypto entries (from {len(all_vulns)} total)")
                return filtered
        except Exception as e:
            print(f"[scraper] CISA KEV error: {e}")
            return cache.get(cache_key, {}).get("data", [])

    async def fetch_all(self) -> Dict:
        """Fetch all data sources with 24h caching. NVD calls are sequential to respect rate limits."""
        nvd_quantum = await self.fetch_nvd("quantum")
        # Small delay between NVD calls to stay within rate limits (5 req/30s without API key)
        await asyncio.sleep(2)
        nvd_crypto = await self.fetch_nvd("cryptography")
        kev = await self.fetch_cisa_kev()

        # Deduplicate CVEs that appear in both keyword results
        seen: set = set()
        all_cves: List[Dict] = []
        for cve in nvd_quantum + nvd_crypto:
            if cve.get("id") and cve["id"] not in seen:
                seen.add(cve["id"])
                all_cves.append(cve)

        return {
            "cves": all_cves,
            "kev": kev,
            "fetched_at": datetime.utcnow().isoformat(),
        }
