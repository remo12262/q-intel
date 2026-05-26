import anthropic
import json
import os
import re
from typing import Dict, List

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are a quantum and cybersecurity threat intelligence analyst.
Extract entities and relationships from vulnerability and security texts to build a knowledge graph.

Entity types:
- Vulnerability: CVE identifiers and security flaws
- Software: software products, libraries, frameworks, hardware
- TechCompany: technology companies, chip makers, hardware vendors
- GovernmentAgency: government agencies, regulatory bodies (NIST, CISA, ENISA)
- Organization: standards bodies, consortia, alliances

Relationship types:
- AFFECTS: vulnerability affects a software or product
- EXPLOITS: attack vector exploits a vulnerability
- MITIGATES: entity or patch mitigates a vulnerability
- PRODUCES: company produces a software or hardware product
- REGULATES: agency regulates an entity or standard
- RELATED_TO: general association

For each relationship, compute a risk_score 0-100:
- 0-30: low risk
- 31-60: moderate risk
- 61-80: high risk
- 81-100: critical risk

Higher risk for: cryptographic weaknesses, quantum-vulnerable algorithms (RSA, ECC, DH),
actively exploited CVEs, post-quantum migration gaps, supply chain exposure.

Respond ONLY with valid JSON, no extra text."""

EXTRACT_PROMPT = """Analyze this cybersecurity text and extract entities and relationships.

Text:
{text}

Respond with this exact JSON:
{{
  "entities": [
    {{
      "id": "unique_slug",
      "label": "Entity Name",
      "type": "EntityType",
      "country": "US/EU/CN/etc or null",
      "description": "brief description",
      "risk_score": 0
    }}
  ],
  "relations": [
    {{
      "source": "entity_id_1",
      "target": "entity_id_2",
      "type": "RELATION_TYPE",
      "fact": "concise description of the relationship",
      "risk_score": 0,
      "date": "YYYY-MM or null"
    }}
  ]
}}"""


class EntityExtractor:

    def _make_slug(self, text: str) -> str:
        return re.sub(r'[^a-z0-9_]', '', text.lower().replace(' ', '_').replace('-', '_'))[:32]

    def _cvss_to_risk(self, cvss_score: float, severity: str) -> int:
        if cvss_score > 0:
            return min(100, int(cvss_score * 10))
        severity_map = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 50, "LOW": 25, "UNKNOWN": 30}
        return severity_map.get(severity.upper(), 30)

    def process_cves(self, cves: List[Dict]) -> Dict:
        """Convert NVD CVE data directly into graph entities (no Claude required)."""
        entities: Dict[str, Dict] = {}
        relations: List[Dict] = []

        for cve in cves:
            cve_id = cve.get("id")
            if not cve_id:
                continue

            risk_score = self._cvss_to_risk(cve.get("cvss_score", 0), cve.get("severity", "UNKNOWN"))
            cve_slug = self._make_slug(cve_id)

            entities[cve_slug] = {
                "id": cve_slug,
                "label": cve_id,
                "type": "Vulnerability",
                "country": None,
                "description": cve.get("description", "")[:300],
                "risk_score": risk_score,
            }

            for product_str in cve.get("affected_products", []):
                parts = product_str.split(":")
                vendor = parts[0].replace("_", " ").title() if parts else ""
                product = parts[1].replace("_", " ").title() if len(parts) > 1 else ""
                label = f"{vendor} {product}".strip() or product_str
                pid = self._make_slug(label)

                if pid not in entities:
                    entities[pid] = {
                        "id": pid,
                        "label": label,
                        "type": "Software",
                        "country": None,
                        "description": "Product affected by quantum/cryptographic vulnerabilities.",
                        "risk_score": 0,
                    }
                entities[pid]["risk_score"] = max(entities[pid]["risk_score"], risk_score // 2)

                relations.append({
                    "source": cve_slug,
                    "target": pid,
                    "type": "AFFECTS",
                    "fact": f"{cve_id} ({cve.get('severity', 'UNKNOWN')}, CVSS {cve.get('cvss_score', 'N/A')}) affects {label}.",
                    "risk_score": risk_score,
                    "date": cve.get("published", "")[:7] or None,
                })

        return {"entities": list(entities.values()), "relations": relations}

    def process_kev(self, kev_entries: List[Dict]) -> Dict:
        """Convert CISA KEV entries into graph entities (no Claude required)."""
        entities: Dict[str, Dict] = {}
        relations: List[Dict] = []

        for entry in kev_entries:
            cve_id = entry.get("id")
            if not cve_id:
                continue

            ransomware = entry.get("known_ransomware", "Unknown")
            risk_score = 95 if ransomware not in ("Unknown", "No Known") else 80
            cve_slug = self._make_slug(cve_id)

            entities[cve_slug] = {
                "id": cve_slug,
                "label": cve_id,
                "type": "Vulnerability",
                "country": None,
                "description": f"[CISA KEV] {entry.get('name', '')}. {entry.get('description', '')}".strip()[:300],
                "risk_score": risk_score,
            }

            vendor = entry.get("vendor", "")
            product = entry.get("product", "")
            if vendor or product:
                label = f"{vendor} {product}".strip()
                pid = self._make_slug(label)
                if pid not in entities:
                    entities[pid] = {
                        "id": pid,
                        "label": label,
                        "type": "Software",
                        "country": None,
                        "description": f"{vendor} product with CISA-confirmed active exploitation.",
                        "risk_score": risk_score // 2,
                    }
                entities[pid]["risk_score"] = max(entities[pid]["risk_score"], risk_score // 2)

                relations.append({
                    "source": cve_slug,
                    "target": pid,
                    "type": "AFFECTS",
                    "fact": f"{cve_id} actively exploited in {label}. Action: {entry.get('required_action', '')}",
                    "risk_score": risk_score,
                    "date": entry.get("date_added", "")[:7] or None,
                })

        return {"entities": list(entities.values()), "relations": relations}

    async def extract(self, text: str, source_id: str = "") -> Dict:
        """Extract entities and relations from text using Claude claude-sonnet-4-6."""
        if not text or len(text.strip()) < 50:
            return {"entities": [], "relations": []}
        try:
            message = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=2000,
                system=SYSTEM_PROMPT,
                tools=[{"type": "web_search_20250305", "name": "web_search"}],
                messages=[{
                    "role": "user",
                    "content": EXTRACT_PROMPT.format(text=text[:3000])
                }]
            )
            raw = next((b.text for b in message.content if hasattr(b, "text")), "").strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            result = json.loads(raw)
            for e in result.get("entities", []):
                if not e.get("id"):
                    e["id"] = self._make_slug(e.get("label", "unknown"))
            for r in result.get("relations", []):
                r["source_doc"] = source_id
            return result
        except Exception as e:
            print(f"[extractor] Error: {e}")
            return {"entities": [], "relations": []}

    async def extract_batch(self, items: List[Dict], text_field: str = "summary") -> Dict:
        """Extract from multiple items and merge results."""
        import asyncio
        all_entities: Dict[str, Dict] = {}
        all_relations: List[Dict] = []

        tasks = [
            self.extract(
                item.get(text_field, "") + " " + item.get("title", ""),
                source_id=item.get("id", "")
            )
            for item in items[:10]
        ]
        results = await asyncio.gather(*tasks)

        for result in results:
            for entity in result.get("entities", []):
                eid = entity["id"]
                if eid not in all_entities:
                    all_entities[eid] = entity
                else:
                    all_entities[eid]["risk_score"] = max(
                        all_entities[eid].get("risk_score", 0),
                        entity.get("risk_score", 0)
                    )
            all_relations.extend(result.get("relations", []))

        return {"entities": list(all_entities.values()), "relations": all_relations}

    async def generate_alerts(self, entities: List[Dict], relations: List[Dict]) -> List[Dict]:
        """Use Claude claude-sonnet-4-6 to generate predictive risk alerts from the graph."""
        if not entities:
            return []

        graph_summary = json.dumps({
            "high_risk_vulnerabilities": [
                e for e in entities if e.get("type") == "Vulnerability" and e.get("risk_score", 0) > 60
            ][:10],
            "high_risk_entities": [
                e for e in entities if e.get("type") != "Vulnerability" and e.get("risk_score", 0) > 60
            ][:5],
            "high_risk_relations": [r for r in relations if r.get("risk_score", 0) > 60][:10],
        }, indent=2)

        try:
            message = client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=1500,
                tools=[{"type": "web_search_20250305", "name": "web_search"}],
                messages=[{
                    "role": "user",
                    "content": f"""Analyze this quantum/cryptography security knowledge graph and generate predictive risk alerts.

{graph_summary}

Generate 3-5 predictive alerts as JSON:
[
  {{
    "id": "alert_slug",
    "title": "Short alert title",
    "description": "Detailed risk description and prediction",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "entities_involved": ["id1", "id2"],
    "predicted_impact": "description of expected impact",
    "timeframe": "e.g. 3-6 months",
    "recommendation": "recommended action"
  }}
]

Respond ONLY with valid JSON."""
                }]
            )
            raw = next((b.text for b in message.content if hasattr(b, "text")), "").strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw)
        except Exception as e:
            print(f"[extractor] Alert generation error: {e}")
            return []
