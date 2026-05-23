import asyncio
from datetime import datetime

REFRESH_INTERVAL = 6 * 60 * 60  # 6 hours in seconds


class Scheduler:

    def __init__(self, scraper, extractor, db):
        self.scraper = scraper
        self.extractor = extractor
        self.db = db
        self.last_run = None

    async def run_once(self):
        print(f"[scheduler] Starting data refresh at {datetime.utcnow().isoformat()}")
        try:
            # 1. Fetch raw data
            data = await self.scraper.fetch_all()
            print(f"[scheduler] Fetched: {len(data['news'])} news, {len(data['cves'])} CVEs, {len(data['papers'])} papers")

            # 2. Extract entities from news
            if data["news"]:
                result = await self.extractor.extract_batch(data["news"], text_field="summary")
                await self.db.upsert_entities(result["entities"])
                await self.db.upsert_relations(result["relations"])
                print(f"[scheduler] Extracted {len(result['entities'])} entities, {len(result['relations'])} relations from news")

            # 3. Extract from papers
            if data["papers"]:
                result = await self.extractor.extract_batch(data["papers"], text_field="summary")
                await self.db.upsert_entities(result["entities"])
                await self.db.upsert_relations(result["relations"])

            # 4. Generate predictive alerts
            nodes = await self.db.get_nodes()
            edges = await self.db.get_edges()
            alerts = await self.extractor.generate_alerts(nodes, edges)
            if alerts:
                await self.db.upsert_alerts(alerts)
                print(f"[scheduler] Generated {len(alerts)} alerts")

            self.last_run = datetime.utcnow().isoformat()
            print(f"[scheduler] Refresh complete at {self.last_run}")

        except Exception as e:
            print(f"[scheduler] Error during refresh: {e}")

    async def run(self):
        """Run forever, refreshing every REFRESH_INTERVAL seconds."""
        while True:
            await self.run_once()
            await asyncio.sleep(REFRESH_INTERVAL)
