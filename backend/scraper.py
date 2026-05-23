import httpx
import feedparser
import os
from datetime import datetime, timedelta
from typing import List, Dict

NEWS_SOURCES = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.wired.com/feed/category/security/latest/rss",
    "https://feeds.arstechnica.com/arstechnica/technology-lab",
    "https://www.enisa.europa.eu/news/enisa-news/RSS",
]

KEYWORDS = [
    "quantum", "semiconductor", "chip", "SMIC", "TSMC", "Nvidia",
    "cryptography", "post-quantum", "AI security", "supply chain",
    "NIS2", "NIST", "cybersecurity", "vulnerability", "CVE",
    "Moore Threads", "Huawei", "export control", "sanctions"
]


class DataScraper:

    async def fetch_news(self) -> List[Dict]:
        """Fetch articles from RSS feeds filtered by keywords."""
        articles = []
        for url in NEWS_SOURCES:
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries[:20]:
                    title = entry.get("title", "")
                    summary = entry.get("summary", "")
                    text = f"{title} {summary}".lower()
                    if any(kw.lower() in text for kw in KEYWORDS):
                        articles.append({
                            "id": entry.get("id", entry.link),
                            "title": title,
                            "summary": summary,
                            "url": entry.get("link", ""),
                            "published": entry.get("published", ""),
                            "source": feed.feed.get("title", url),
                        })
            except Exception as e:
                print(f"[scraper] RSS error {url}: {e}")
        return articles

    async def fetch_cve(self) -> List[Dict]:
        """Fetch recent CVEs from NVD API related to AI/quantum tech."""
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": "AI quantum cryptography chip semiconductor",
            "pubStartDate": (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000"),
            "pubEndDate": datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999"),
            "resultsPerPage": 20,
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, params=params)
                data = r.json()
                cves = []
                for item in data.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    desc = cve.get("descriptions", [{}])[0].get("value", "")
                    cves.append({
                        "id": cve.get("id"),
                        "description": desc,
                        "severity": item.get("cve", {}).get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN"),
                        "published": cve.get("published", ""),
                    })
                return cves
        except Exception as e:
            print(f"[scraper] NVD error: {e}")
            return []

    async def fetch_opensanctions(self) -> List[Dict]:
        """Fetch sanctioned tech entities from OpenSanctions."""
        url = "https://api.opensanctions.org/search/default"
        params = {"q": "semiconductor quantum AI technology", "limit": 30}
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, params=params)
                data = r.json()
                entities = []
                for result in data.get("results", []):
                    entities.append({
                        "id": result.get("id"),
                        "name": result.get("caption"),
                        "type": result.get("schema"),
                        "country": result.get("properties", {}).get("country", [None])[0],
                        "sanctioned": True,
                    })
                return entities
        except Exception as e:
            print(f"[scraper] OpenSanctions error: {e}")
            return []

    async def fetch_arxiv(self) -> List[Dict]:
        """Fetch recent quantum/AI security papers from ArXiv."""
        url = "http://export.arxiv.org/api/query"
        params = {
            "search_query": "ti:quantum+AND+ti:cryptography+OR+ti:post-quantum+AND+ti:security",
            "max_results": 15,
            "sortBy": "submittedDate",
            "sortOrder": "descending",
        }
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                r = await client.get(url, params=params)
                feed = feedparser.parse(r.text)
                papers = []
                for entry in feed.entries:
                    papers.append({
                        "id": entry.get("id", ""),
                        "title": entry.get("title", ""),
                        "summary": entry.get("summary", "")[:500],
                        "authors": [a.get("name") for a in entry.get("authors", [])],
                        "published": entry.get("published", ""),
                    })
                return papers
        except Exception as e:
            print(f"[scraper] ArXiv error: {e}")
            return []

    async def fetch_all(self) -> Dict:
        """Run all scrapers and return combined results."""
        import asyncio
        news, cves, sanctions, papers = await asyncio.gather(
            self.fetch_news(),
            self.fetch_cve(),
            self.fetch_opensanctions(),
            self.fetch_arxiv(),
        )
        return {
            "news": news,
            "cves": cves,
            "sanctions": sanctions,
            "papers": papers,
            "fetched_at": datetime.utcnow().isoformat(),
        }
