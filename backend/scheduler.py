import asyncio
from datetime import datetime

REFRESH_INTERVAL = 24 * 60 * 60  # 24 hours, matching the data cache TTL


class Scheduler:

    def __init__(self, scraper, extractor, db):
        self.scraper = scraper
        self.extractor = extractor
        self.db = db
        self.last_run = None

    async def run_once(self):
        print(f"[scheduler] Starting data refresh at {datetime.utcnow().isoformat()}")
        try:
            # 1. Fetch real data from NVD NIST and CISA KEV (cached for 24h)
            data = await self.scraper.fetch_all()
            print(f"[scheduler] Fetched: {len(data['cves'])} CVEs, {len(data['kev'])} KEV entries")

            # 2. Process NVD CVEs directly into graph nodes/edges (no Claude)
            if data["cves"]:
                result = self.extractor.process_cves(data["cves"])
                await self.db.upsert_entities(result["entities"])
                await self.db.upsert_relations(result["relations"])
                print(f"[scheduler] CVE graph: {len(result['entities'])} entities, {len(result['relations'])} relations")

            # 3. Process CISA KEV entries (no Claude, higher risk scores for actively exploited)
            if data["kev"]:
                result = self.extractor.process_kev(data["kev"])
                await self.db.upsert_entities(result["entities"])
                await self.db.upsert_relations(result["relations"])
                print(f"[scheduler] KEV graph: {len(result['entities'])} entities from CISA KEV")

            # 4. Claude analysis of top HIGH/CRITICAL CVEs for additional threat intel
            high_severity = [
                {"id": c["id"], "title": c["id"], "summary": c["description"]}
                for c in data["cves"]
                if c.get("severity") in ("CRITICAL", "HIGH") and c.get("description")
            ][:5]
            if high_severity:
                result = await self.extractor.extract_batch(high_severity, text_field="summary")
                await self.db.upsert_entities(result["entities"])
                await self.db.upsert_relations(result["relations"])
                print(f"[scheduler] Claude extracted {len(result['entities'])} additional entities from high-severity CVEs")

            # 5. Generate predictive alerts from the full graph
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
