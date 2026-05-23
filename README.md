# Q-INTEL — Quantum & AI Security Intelligence Graph

Knowledge graph predittivo per la sicurezza AI e quantum computing.
Mappa automaticamente relazioni tra aziende chip, laboratori quantum, governi e investitori.
Genera alert predittivi su rischi per le infrastrutture critiche italiane/EU.

## Stack
- **Backend:** FastAPI + SQLite (upgradabile a Neo4j) + Claude AI
- **Frontend:** React + Vite + Canvas 2D
- **Deploy:** Render.com
- **Dati:** NewsAPI RSS, NVD/NIST CVE, OpenSanctions, ArXiv

## Setup locale

### Backend
```bash
cd backend
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
uvicorn main:app --reload
```

### Frontend
```bash
cd frontend
npm install
VITE_API_URL=http://localhost:8000 npm run dev
```

## Deploy su Render

1. Push su GitHub
2. New Blueprint → collega repo → render.yaml rilevato automaticamente
3. Aggiungi env var `ANTHROPIC_API_KEY` nel dashboard Render
4. Aggiungi env var `VITE_API_URL` con URL del backend Render

## Architettura

```
Fonti automatiche (ogni 6h)
├── RSS: TheHackersNews, Wired, ArsTechnica, ENISA
├── NVD API: CVE AI/quantum/chip
├── OpenSanctions: entità sanzionate
└── ArXiv: paper post-quantum
         ↓
Claude AI (extractor.py)
├── Estrae entità tipizzate
├── Estrae relazioni con fact
└── Genera alert predittivi
         ↓
SQLite GraphDB (upgradabile Neo4j)
         ↓
React Frontend
├── Grafo interattivo (Canvas + force layout)
├── Pannello dettaglio nodo + relazioni
├── Alert predittivi per severità
└── Risk Score ranking
```

## Prossimi sviluppi
- [ ] Autenticazione utenti
- [ ] Export grafo in formato GEXF/GraphML
- [ ] Integrazione Neo4j AuraDB
- [ ] API webhook per alert real-time
- [ ] App 2: Political Intelligence Graph
- [ ] App 3: Health System Intelligence Graph
