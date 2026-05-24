import aiosqlite
import json
import os
from typing import List, Dict, Optional
from datetime import datetime

DB_PATH = os.environ.get("DB_PATH", "q_intel.db")


class GraphDB:

    async def init(self):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    type TEXT NOT NULL,
                    domain TEXT DEFAULT 'quantum',
                    country TEXT,
                    description TEXT,
                    risk_score INTEGER DEFAULT 0,
                    created_at TEXT,
                    updated_at TEXT
                );
                CREATE TABLE IF NOT EXISTS edges (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    target TEXT NOT NULL,
                    type TEXT NOT NULL,
                    fact TEXT,
                    risk_score INTEGER DEFAULT 0,
                    source_doc TEXT,
                    date TEXT,
                    created_at TEXT,
                    FOREIGN KEY(source) REFERENCES nodes(id),
                    FOREIGN KEY(target) REFERENCES nodes(id)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'MEDIUM',
                    entities_involved TEXT,
                    predicted_impact TEXT,
                    timeframe TEXT,
                    recommendation TEXT,
                    created_at TEXT,
                    is_read INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
                CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
                CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            """)
            await db.commit()
            # Seed with baseline data if empty
            cursor = await db.execute("SELECT COUNT(*) FROM nodes")
            count = (await cursor.fetchone())[0]
            if count == 0:
                await self._seed_baseline(db)

    async def _seed_baseline(self, db):
        """Seed with known baseline entities in the quantum/AI security domain."""
        now = datetime.utcnow().isoformat()
        nodes = [
            ("tsmc",       "TSMC",              "TechCompany",    "quantum", "TW", "Taiwan Semiconductor Manufacturing Company. Produttore chip più avanzato al mondo.", 45),
            ("nvidia",     "NVIDIA",             "TechCompany",    "quantum", "US", "Azienda GPU leader per AI computing. Target geopolitico strategico.", 30),
            ("smic",       "SMIC",               "TechCompany",    "quantum", "CN", "Semiconductor Manufacturing International Corp. Principale foundry cinese.", 75),
            ("moore_t",    "Moore Threads",      "TechCompany",    "quantum", "CN", "Produttore GPU cinese con legami SMIC. Rilevante per quantum AI.", 80),
            ("huawei",     "Huawei",             "TechCompany",    "quantum", "CN", "Multinazionale telecom/chip cinese sotto sanzioni US. HiSilicon chip.", 85),
            ("nist_us",    "NIST",               "GovernmentAgency","quantum","US", "National Institute of Standards and Technology. Definisce standard FIPS post-quantum.", 10),
            ("enisa_eu",   "ENISA",              "GovernmentAgency","quantum","EU", "EU Agency for Cybersecurity. Pubblica linee guida NIS2 e quantum readiness.", 10),
            ("bis_us",     "BIS / DOC",          "GovernmentAgency","quantum","US", "Bureau of Industry and Security. Gestisce export controls chip avanzati.", 15),
            ("acn_it",     "ACN Italia",         "GovernmentAgency","quantum","IT", "Agenzia per la Cybersicurezza Nazionale. Punto di riferimento NIS2 in Italia.", 10),
            ("cisa_us",    "CISA",               "GovernmentAgency","quantum","US", "Cybersecurity and Infrastructure Security Agency. Publishes KEV catalog of actively exploited vulnerabilities.", 10),
            ("softbank",   "SoftBank",           "InvestorInst",   "quantum", "JP", "Vision Fund. Investitore globale AI/chip. Partecipazioni strategiche.", 40),
            ("sequoia_cn", "Sequoia China",      "InvestorInst",   "quantum", "CN", "Braccio cinese Sequoia Capital. Investe in AI e semiconduttori cinesi.", 70),
            ("arm",        "ARM Holdings",       "TechCompany",    "quantum", "UK", "Designer architetture CPU/GPU. Licenze a quasi tutti i produttori chip.", 35),
            ("ibm_q",      "IBM Quantum",        "TechCompany",    "quantum", "US", "Divisione quantum computing IBM. Leader ricerca quantum hardware.", 20),
            ("google_q",   "Google Quantum AI",  "TechCompany",    "quantum", "US", "Divisione quantum Google. Quantum supremacy 2019.", 20),
        ]
        edges = [
            ("e1",  "moore_t",   "smic",     "COLLABORA_CON", "Moore Threads finanziato da SMIC per sviluppo chip AI avanzati. (dic 2023)", 82, "2023-12"),
            ("e2",  "sequoia_cn","smic",     "INVESTE_IN",    "Sequoia China ha partecipazioni in aziende dell'ecosistema SMIC.", 72, "2022-06"),
            ("e3",  "huawei",    "smic",     "COLLABORA_CON", "Huawei usa SMIC come foundry alternativa dopo sanzioni TSMC.", 88, "2020-09"),
            ("e4",  "bis_us",    "huawei",   "REGOLA",        "BIS inserisce Huawei nella Entity List. Export restrictions chip USA.", 15, "2019-05"),
            ("e5",  "bis_us",    "smic",     "REGOLA",        "BIS restringe export di chip equipment a SMIC. Limita accesso EUV.", 15, "2020-12"),
            ("e6",  "nist_us",   "enisa_eu", "COLLABORA_CON", "NIST e ENISA collaborano su standard post-quantum crittografici.", 5,  "2022-01"),
            ("e7",  "acn_it",    "enisa_eu", "MEMBRO_DI",     "ACN Italia opera nel framework ENISA per la cybersicurezza EU.", 5,  "2021-01"),
            ("e8",  "softbank",  "arm",      "CONTROLLA",     "SoftBank acquisisce ARM nel 2016 per 32 miliardi USD.", 38, "2016-09"),
            ("e9",  "tsmc",      "nist_us",  "COLLABORA_CON", "TSMC collabora con NIST su standard per chip quantum-safe.", 12, "2023-03"),
            ("e10", "moore_t",   "acn_it",   "RISCHIO_PER",   "Chip Moore Threads potenzialmente in infrastrutture IT italiane via supply chain.", 78, "2024-01"),
        ]
        await db.executemany(
            "INSERT OR IGNORE INTO nodes VALUES (?,?,?,?,?,?,?,?,?)",
            [(n[0], n[1], n[2], n[3], n[4], n[5], n[6], now, now) for n in nodes]
        )
        await db.executemany(
            "INSERT OR IGNORE INTO edges VALUES (?,?,?,?,?,?,?,?,?)",
            [(e[0], e[1], e[2], e[3], e[4], e[5], "", e[6], now) for e in edges]
        )
        await db.commit()

    async def get_nodes(self, domain: Optional[str] = None) -> List[Dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            if domain:
                cursor = await db.execute("SELECT * FROM nodes WHERE domain=? ORDER BY risk_score DESC", (domain,))
            else:
                cursor = await db.execute("SELECT * FROM nodes ORDER BY risk_score DESC")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_edges(self, domain: Optional[str] = None) -> List[Dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            if domain:
                cursor = await db.execute("""
                    SELECT e.* FROM edges e
                    JOIN nodes n ON e.source = n.id
                    WHERE n.domain = ?
                """, (domain,))
            else:
                cursor = await db.execute("SELECT * FROM edges ORDER BY risk_score DESC")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_node(self, node_id: str) -> Optional[Dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM nodes WHERE id=?", (node_id,))
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def get_node_relations(self, node_id: str) -> List[Dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT e.*, 
                    ns.label as source_label, ns.type as source_type,
                    nt.label as target_label, nt.type as target_type
                FROM edges e
                JOIN nodes ns ON e.source = ns.id
                JOIN nodes nt ON e.target = nt.id
                WHERE e.source=? OR e.target=?
                ORDER BY e.risk_score DESC
            """, (node_id, node_id))
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_alerts(self, severity: Optional[str] = None) -> List[Dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            if severity:
                cursor = await db.execute("SELECT * FROM alerts WHERE severity=? ORDER BY created_at DESC", (severity,))
            else:
                cursor = await db.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT 50")
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_risk_scores(self) -> List[Dict]:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("""
                SELECT id, label, type, country, risk_score
                FROM nodes ORDER BY risk_score DESC LIMIT 20
            """)
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]

    async def get_stats(self) -> Dict:
        async with aiosqlite.connect(DB_PATH) as db:
            n = (await (await db.execute("SELECT COUNT(*) FROM nodes")).fetchone())[0]
            e = (await (await db.execute("SELECT COUNT(*) FROM edges")).fetchone())[0]
            a = (await (await db.execute("SELECT COUNT(*) FROM alerts WHERE is_read=0")).fetchone())[0]
            cr = (await (await db.execute("SELECT COUNT(*) FROM nodes WHERE risk_score > 60")).fetchone())[0]
            return {"nodes": n, "edges": e, "unread_alerts": a, "critical_nodes": cr}

    async def upsert_entities(self, entities: List[Dict]):
        now = datetime.utcnow().isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            for e in entities:
                await db.execute("""
                    INSERT INTO nodes (id, label, type, domain, country, description, risk_score, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        risk_score = MAX(risk_score, excluded.risk_score),
                        updated_at = excluded.updated_at
                """, (
                    e.get("id"), e.get("label"), e.get("type", "Organization"),
                    "quantum", e.get("country"), e.get("description"),
                    e.get("risk_score", 0), now, now
                ))
            await db.commit()

    async def upsert_relations(self, relations: List[Dict]):
        now = datetime.utcnow().isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            for r in relations:
                rid = f"{r.get('source')}_{r.get('target')}_{r.get('type')}"
                await db.execute("""
                    INSERT INTO edges (id, source, target, type, fact, risk_score, source_doc, date, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        risk_score = MAX(risk_score, excluded.risk_score)
                """, (
                    rid, r.get("source"), r.get("target"), r.get("type", "COLLEGATO_A"),
                    r.get("fact"), r.get("risk_score", 0),
                    r.get("source_doc", ""), r.get("date"), now
                ))
            await db.commit()

    async def upsert_alerts(self, alerts: List[Dict]):
        now = datetime.utcnow().isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            for a in alerts:
                await db.execute("""
                    INSERT OR REPLACE INTO alerts
                    (id, title, description, severity, entities_involved, predicted_impact, timeframe, recommendation, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                    a.get("id", f"alert_{now}"), a.get("title"), a.get("description"),
                    a.get("severity", "MEDIUM"),
                    json.dumps(a.get("entities_involved", [])),
                    a.get("predicted_impact"), a.get("timeframe"),
                    a.get("recommendation"), now
                ))
            await db.commit()
