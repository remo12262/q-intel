import json
from typing import List, Dict, Optional
from datetime import datetime


class GraphDB:
    def __init__(self):
        self.nodes: Dict[str, Dict] = {}
        self.edges: Dict[str, Dict] = {}
        self.alerts: Dict[str, Dict] = {}

    async def init(self):
        if not self.nodes:
            self._seed_baseline()

    def _seed_baseline(self):
        now = datetime.utcnow().isoformat()
        nodes = [
            ("tsmc",       "TSMC",              "TechCompany",     "quantum", "TW", "Taiwan Semiconductor Manufacturing Company. Produttore chip più avanzato al mondo.", 45),
            ("nvidia",     "NVIDIA",             "TechCompany",     "quantum", "US", "Azienda GPU leader per AI computing. Target geopolitico strategico.", 30),
            ("smic",       "SMIC",               "TechCompany",     "quantum", "CN", "Semiconductor Manufacturing International Corp. Principale foundry cinese.", 75),
            ("moore_t",    "Moore Threads",      "TechCompany",     "quantum", "CN", "Produttore GPU cinese con legami SMIC. Rilevante per quantum AI.", 80),
            ("huawei",     "Huawei",             "TechCompany",     "quantum", "CN", "Multinazionale telecom/chip cinese sotto sanzioni US. HiSilicon chip.", 85),
            ("nist_us",    "NIST",               "GovernmentAgency","quantum", "US", "National Institute of Standards and Technology. Definisce standard FIPS post-quantum.", 10),
            ("enisa_eu",   "ENISA",              "GovernmentAgency","quantum", "EU", "EU Agency for Cybersecurity. Pubblica linee guida NIS2 e quantum readiness.", 10),
            ("bis_us",     "BIS / DOC",          "GovernmentAgency","quantum", "US", "Bureau of Industry and Security. Gestisce export controls chip avanzati.", 15),
            ("acn_it",     "ACN Italia",         "GovernmentAgency","quantum", "IT", "Agenzia per la Cybersicurezza Nazionale. Punto di riferimento NIS2 in Italia.", 10),
            ("cisa_us",    "CISA",               "GovernmentAgency","quantum", "US", "Cybersecurity and Infrastructure Security Agency. Pubblica KEV catalog.", 10),
            ("softbank",   "SoftBank",           "InvestorInst",    "quantum", "JP", "Vision Fund. Investitore globale AI/chip. Partecipazioni strategiche.", 40),
            ("sequoia_cn", "Sequoia China",      "InvestorInst",    "quantum", "CN", "Braccio cinese Sequoia Capital. Investe in AI e semiconduttori cinesi.", 70),
            ("arm",        "ARM Holdings",       "TechCompany",     "quantum", "UK", "Designer architetture CPU/GPU. Licenze a quasi tutti i produttori chip.", 35),
            ("ibm_q",      "IBM Quantum",        "TechCompany",     "quantum", "US", "Divisione quantum computing IBM. Leader ricerca quantum hardware.", 20),
            ("google_q",   "Google Quantum AI",  "TechCompany",     "quantum", "US", "Divisione quantum Google. Quantum supremacy 2019.", 20),
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
        for n in nodes:
            self.nodes[n[0]] = {
                "id": n[0], "label": n[1], "type": n[2], "domain": n[3],
                "country": n[4], "description": n[5], "risk_score": n[6],
                "created_at": now, "updated_at": now,
            }
        for e in edges:
            self.edges[e[0]] = {
                "id": e[0], "source": e[1], "target": e[2], "type": e[3],
                "fact": e[4], "risk_score": e[5], "source_doc": "",
                "date": e[6], "created_at": now,
            }

    async def get_nodes(self, domain: Optional[str] = None) -> List[Dict]:
        nodes = list(self.nodes.values())
        if domain:
            nodes = [n for n in nodes if n.get("domain") == domain]
        return sorted(nodes, key=lambda n: n.get("risk_score", 0), reverse=True)

    async def get_edges(self, domain: Optional[str] = None) -> List[Dict]:
        edges = list(self.edges.values())
        if domain:
            edges = [e for e in edges if self.nodes.get(e["source"], {}).get("domain") == domain]
        return sorted(edges, key=lambda e: e.get("risk_score", 0), reverse=True)

    async def get_node(self, node_id: str) -> Optional[Dict]:
        return self.nodes.get(node_id)

    async def get_node_relations(self, node_id: str) -> List[Dict]:
        results = []
        for e in self.edges.values():
            if e["source"] == node_id or e["target"] == node_id:
                src = self.nodes.get(e["source"], {})
                tgt = self.nodes.get(e["target"], {})
                results.append({
                    **e,
                    "source_label": src.get("label", ""),
                    "source_type":  src.get("type", ""),
                    "target_label": tgt.get("label", ""),
                    "target_type":  tgt.get("type", ""),
                })
        return sorted(results, key=lambda e: e.get("risk_score", 0), reverse=True)

    async def get_alerts(self, severity: Optional[str] = None) -> List[Dict]:
        alerts = list(self.alerts.values())
        if severity:
            alerts = [a for a in alerts if a.get("severity") == severity]
        return sorted(alerts, key=lambda a: a.get("created_at", ""), reverse=True)[:50]

    async def get_risk_scores(self) -> List[Dict]:
        nodes = sorted(self.nodes.values(), key=lambda n: n.get("risk_score", 0), reverse=True)
        return [
            {"id": n["id"], "label": n["label"], "type": n["type"],
             "country": n.get("country"), "risk_score": n.get("risk_score", 0)}
            for n in nodes[:20]
        ]

    async def get_stats(self) -> Dict:
        unread = sum(1 for a in self.alerts.values() if not a.get("is_read"))
        critical = sum(1 for n in self.nodes.values() if n.get("risk_score", 0) > 60)
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "unread_alerts": unread,
            "critical_nodes": critical,
        }

    async def upsert_entities(self, entities: List[Dict]):
        now = datetime.utcnow().isoformat()
        for e in entities:
            eid = e.get("id")
            if not eid:
                continue
            if eid in self.nodes:
                self.nodes[eid]["risk_score"] = max(
                    self.nodes[eid].get("risk_score", 0), e.get("risk_score", 0)
                )
                self.nodes[eid]["updated_at"] = now
            else:
                self.nodes[eid] = {
                    "id": eid, "label": e.get("label", ""),
                    "type": e.get("type", "Organization"), "domain": "quantum",
                    "country": e.get("country"), "description": e.get("description", ""),
                    "risk_score": e.get("risk_score", 0),
                    "created_at": now, "updated_at": now,
                }

    async def upsert_relations(self, relations: List[Dict]):
        now = datetime.utcnow().isoformat()
        for r in relations:
            rid = f"{r.get('source')}_{r.get('target')}_{r.get('type')}"
            if rid in self.edges:
                self.edges[rid]["risk_score"] = max(
                    self.edges[rid].get("risk_score", 0), r.get("risk_score", 0)
                )
            else:
                self.edges[rid] = {
                    "id": rid, "source": r.get("source"), "target": r.get("target"),
                    "type": r.get("type", "RELATED_TO"), "fact": r.get("fact"),
                    "risk_score": r.get("risk_score", 0),
                    "source_doc": r.get("source_doc", ""), "date": r.get("date"),
                    "created_at": now,
                }

    async def upsert_alerts(self, alerts: List[Dict]):
        now = datetime.utcnow().isoformat()
        for a in alerts:
            aid = a.get("id", f"alert_{now}")
            self.alerts[aid] = {
                "id": aid, "title": a.get("title"), "description": a.get("description"),
                "severity": a.get("severity", "MEDIUM"),
                "entities_involved": json.dumps(a.get("entities_involved", [])),
                "predicted_impact": a.get("predicted_impact"),
                "timeframe": a.get("timeframe"), "recommendation": a.get("recommendation"),
                "created_at": now, "is_read": False,
            }
