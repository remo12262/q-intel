import anthropic
import json
import os
from typing import Dict, List

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """Sei un sistema di intelligence per la sicurezza AI e quantum computing.
Il tuo compito è estrarre entità e relazioni da testi per costruire un knowledge graph.

Tipi di entità:
- TechCompany: aziende tech, chip maker, AI companies
- GovernmentAgency: agenzie governative, ministeri, enti regolatori
- Person: CEO, ricercatori, policy maker
- InvestorInstitution: fondi, venture capital, banche statali
- Organization: organizzazioni, consorzi, alleanze
- PolicyMaker: decisori politici, parlamentari
- MediaOutlet: media, giornali, riviste

Tipi di relazione:
- FINANZIA: A finanzia B
- CONTROLLA: A controlla B
- COLLABORA_CON: A collabora con B
- RISCHIO_PER: A rappresenta un rischio per B
- MEMBRO_DI: A è membro di B
- REGOLA: A regola B
- PRODUCE: A produce B
- INVESTE_IN: A investe in B
- COLLEGATO_A: A è collegato a B

Per ogni relazione calcola un risk_score da 0 a 100:
- 0-30: basso rischio
- 31-60: rischio moderato
- 61-80: rischio alto
- 81-100: rischio critico

Rischio alto se coinvolge stati avversari (Cina, Russia, Iran, Corea del Nord),
catene di fornitura critiche, vulnerabilità crittografiche, elusione sanzioni.

Rispondi SOLO con JSON valido, nessun testo extra."""

EXTRACT_PROMPT = """Analizza questo testo ed estrai entità e relazioni.

Testo:
{text}

Rispondi con questo JSON esatto:
{{
  "entities": [
    {{
      "id": "slug_univoco",
      "label": "Nome Entità",
      "type": "TipoEntità",
      "country": "IT/US/CN/etc o null",
      "description": "breve descrizione",
      "risk_score": 0-100
    }}
  ],
  "relations": [
    {{
      "source": "id_entità_1",
      "target": "id_entità_2",
      "type": "TIPO_RELAZIONE",
      "fact": "descrizione concisa della relazione",
      "risk_score": 0-100,
      "date": "YYYY-MM o null"
    }}
  ]
}}"""


class EntityExtractor:

    def _make_slug(self, text: str) -> str:
        import re
        return re.sub(r'[^a-z0-9_]', '', text.lower().replace(' ', '_'))[:32]

    async def extract(self, text: str, source_id: str = "") -> Dict:
        """Extract entities and relations from text using Claude."""
        if not text or len(text.strip()) < 50:
            return {"entities": [], "relations": []}
        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                system=SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": EXTRACT_PROMPT.format(text=text[:3000])
                }]
            )
            raw = message.content[0].text.strip()
            # Clean markdown fences if present
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            result = json.loads(raw)
            # Normalize IDs
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
            for item in items[:10]  # limit to avoid rate limits
        ]
        results = await asyncio.gather(*tasks)

        for result in results:
            for entity in result.get("entities", []):
                eid = entity["id"]
                if eid not in all_entities:
                    all_entities[eid] = entity
                else:
                    # Merge: keep higher risk score
                    existing = all_entities[eid]
                    existing["risk_score"] = max(
                        existing.get("risk_score", 0),
                        entity.get("risk_score", 0)
                    )
            all_relations.extend(result.get("relations", []))

        return {
            "entities": list(all_entities.values()),
            "relations": all_relations,
        }

    async def generate_alerts(self, entities: List[Dict], relations: List[Dict]) -> List[Dict]:
        """Use Claude to generate predictive risk alerts from the graph."""
        if not entities:
            return []

        graph_summary = json.dumps({
            "high_risk_entities": [e for e in entities if e.get("risk_score", 0) > 60][:10],
            "high_risk_relations": [r for r in relations if r.get("risk_score", 0) > 60][:10],
        }, indent=2)

        try:
            message = client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1500,
                messages=[{
                    "role": "user",
                    "content": f"""Analizza questo knowledge graph di sicurezza AI/quantum e genera alert predittivi.

{graph_summary}

Genera 3-5 alert predittivi in formato JSON:
[
  {{
    "id": "alert_slug",
    "title": "Titolo breve alert",
    "description": "Descrizione dettagliata del rischio e previsione",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "entities_involved": ["id1", "id2"],
    "predicted_impact": "descrizione impatto atteso",
    "timeframe": "es. 3-6 mesi",
    "recommendation": "azione consigliata"
  }}
]

Rispondi SOLO con JSON valido."""
                }]
            )
            raw = message.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            return json.loads(raw)
        except Exception as e:
            print(f"[extractor] Alert generation error: {e}")
            return []
