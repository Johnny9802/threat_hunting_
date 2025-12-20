# 🚀 New Features - Threat Hunting Playbook

## Panoramica delle Nuove Funzionalità

Sono state implementate tre funzionalità principali che trasformano l'applicazione in un vero **centralizzatore di conoscenza** per threat hunting:

### 1. ✏️ CRUD Completo Playbook
### 2. 🎯 MITRE Matrix 2.0 Interattiva
### 3. 🤖 Suggerimenti AI per Gap Coverage

---

## 1. CRUD Playbook - Gestione Completa

### Cosa è Stato Aggiunto

**Backend API Endpoints:**
- `POST /api/playbooks` - Crea nuovo playbook
- `PUT /api/playbooks/{id}` - Aggiorna playbook esistente
- `DELETE /api/playbooks/{id}` - Elimina playbook

**Frontend Components:**
- `PlaybookForm.tsx` - Form guidato per creazione/modifica playbook
- Validazione completa con Pydantic
- Salvataggio automatico file YAML e query

### Come Usare

#### Creare un Nuovo Playbook

1. Vai su [http://localhost:3000/](http://localhost:3000/)
2. Clicca sul pulsante **"New Playbook"** in alto a destra
3. Compila il form con tutte le informazioni:
   - **Basic Info**: ID, Nome, Descrizione, Autore
   - **MITRE Mapping**: Tecnica, Tattica, Sub-tecniche, Severità
   - **Hunt Details**: Ipotesi, Data Sources, Steps, False Positives
   - **Detection Queries**: Query Splunk, Elastic, Sigma
   - **IOCs**: Aggiungi indicatori di compromissione
   - **Metadata**: Tags e referenze

4. Clicca **"Create Playbook"**

Il sistema creerà automaticamente:
```
playbooks/techniques/T1234-nome-tattica/
├── playbook.yaml
└── queries/
    ├── splunk.spl
    ├── elastic.kql
    └── sigma.yml
```

#### Modificare un Playbook Esistente

1. Vai al dettaglio di un playbook
2. Clicca **"Edit"**
3. Modifica i campi necessari
4. Clicca **"Update Playbook"**

#### Eliminare un Playbook

1. Vai al dettaglio di un playbook
2. Clicca **"Delete"**
3. Conferma l'eliminazione

⚠️ L'eliminazione rimuove l'intera directory del playbook!

---

## 2. MITRE Matrix 2.0 - Visualizzazione Interattiva

### Cosa è Stato Aggiunto

**Nuova Matrice Dinamica con:**
- ✅ Heatmap Coverage - Intensità colore in base al numero di playbook
- ✅ Due modalità di visualizzazione: Matrix View & List View
- ✅ Interattività avanzata - Click su tactic → techniques → playbooks
- ✅ Statistiche dettagliate per coverage
- ✅ Gap analysis automatica

### Heatmap Color Legend

La matrice usa un sistema a colori per mostrare la copertura:

| Colore | Coverage | Significato |
|--------|----------|-------------|
| 🟫 Grigio Scuro | 0 playbook | Nessuna copertura |
| 🔵 Blu Scuro | 1 playbook | Copertura bassa |
| 🔷 Ciano | 2 playbook | Copertura media |
| 🟢 Verde | 3 playbook | Buona copertura |
| 🟠 Arancione | 4+ playbook | Copertura eccellente |

### Come Navigare la Matrice

**Vista Matrice:**
1. Vai su [http://localhost:3000/mitre](http://localhost:3000/mitre)
2. Vedi tutte le 14 tattiche MITRE ATT&CK
3. Clicca su una tattica → Mostra le tecniche coperte
4. Clicca su una tecnica → Mostra i playbook correlati
5. Clicca su un playbook → Vai ai dettagli

**Vista Lista:**
1. Switcha a "List View" per una visualizzazione più compatta
2. Espandi/comprimi tattiche a piacimento
3. Stessa navigazione drill-down

**Coverage Stats:**
- Vedi in tempo reale: Tecniche coperte, Playbook totali, Coverage %, Gap %

---

## 3. AI Gap Analysis & Suggestions

### Cosa è Stato Aggiunto

**Backend Endpoint:**
- `GET /api/mitre/gaps` - Analizza gap coverage e ottieni suggerimenti AI

**Features:**
- Calcola automaticamente le tecniche non coperte
- Identifica tattiche con bassa copertura
- Suggerimenti AI su:
  - Top 3 tecniche critiche da coprire
  - Tattiche che necessitano più playbook
  - Raccomandazioni prioritarie

### Come Usare

#### Via API

```bash
curl http://localhost:8000/api/mitre/gaps
```

Risposta:
```json
{
  "total_techniques": 193,
  "covered_techniques": 8,
  "coverage_percentage": 4.1,
  "tactic_coverage": {
    "initial-access": {
      "techniques": ["T1566"],
      "playbooks": 1
    },
    ...
  },
  "ai_suggestions": "Based on your coverage...",
  "gaps": {
    "uncovered_count": 185,
    "tactics_needing_attention": ["reconnaissance", "resource-development", ...]
  }
}
```

#### Via Frontend

1. Vai alla MITRE Matrix
2. Guarda le statistiche di coverage
3. Le tattiche con meno di 3 tecniche sono evidenziate
4. Clicca su "Add Playbook" per le tattiche con gap
5. Usa le raccomandazioni AI per prioritizzare

---

## Workflow Consigliato

### Per Analizzare la Copertura

1. **Controlla Dashboard**
   - Vedi overview generale
   - Identifica aree critiche

2. **Vai alla MITRE Matrix**
   - Analizza coverage per tattica
   - Identifica gap visuali tramite heatmap
   - Drill-down su aree scoperte

3. **Ottieni Suggerimenti AI**
   - Chiamata a `/api/mitre/gaps`
   - Ricevi raccomandazioni prioritarie
   - Pianifica nuovi playbook

4. **Crea Nuovi Playbook**
   - Usa "New Playbook" button
   - Compila form guidato
   - Salva e visualizza copertura migliorata

### Per Aggiungere Knowledge

1. **Ricerca Playbook Simili**
   - Cerca nella lista esistente
   - Verifica se esiste già copertura

2. **Crea Playbook Guidato**
   - Vai a `/playbook/new`
   - Segui wizard step-by-step
   - Aggiungi query testate per ogni SIEM

3. **Verifica Coverage**
   - Torna alla MITRE Matrix
   - Vedi aggiornamento immediato heatmap
   - Verifica statistiche

---

## Integrazione Futura con Splunk

### Preparazione Attuale

Tutti i playbook ora includono:
- **Query Splunk SPL** - Pronte per import
- **Metadata completa** - MITRE mapping, severità, data sources
- **Structure standardizzata** - Schema validato

### Prossimi Passi (Splunk App)

L'architettura attuale supporta:

```
┌──────────────────┐      REST API Sync     ┌─────────────────┐
│   TH Playbook    │ ←────────────────────→ │   Splunk App    │
│  (Central Hub)   │   Push/Pull Playbooks  │  (Deployment)   │
└──────────────────┘                         └─────────────────┘
        │                                            │
        ├─ Crea/Modifica Playbook                  ├─ Auto-deploy Alerts
        ├─ MITRE Coverage Analysis                 ├─ Correlation Searches
        ├─ AI Recommendations                      ├─ Dashboards
        └─ Versioning                               └─ Investigation Workbench
```

**Features Splunk App (Pianificate):**
- Sync automatico playbook dal hub
- Deploy query come Splunk Alerts
- Dashboard coverage MITRE
- Investigation workspace
- Real-time threat correlation

---

## Testing

### Avviare l'Applicazione

```bash
# Backend API
cd threat-hunting-playbook
source venv/bin/activate
python -m uvicorn api.main:app --reload --port 8000

# Frontend
cd guiweb
npm install
npm run dev
```

### Test Cases

#### Test 1: Creare Playbook

```bash
curl -X POST http://localhost:8000/api/playbooks \
  -H "Content-Type: application/json" \
  -d '{
    "id": "PB-T1234-001",
    "name": "Test Playbook",
    "description": "Testing CRUD",
    "mitre": {
      "technique": "T1234",
      "tactic": "Execution"
    },
    "severity": "high",
    "author": "Test Author",
    "hunt_hypothesis": "Test hypothesis",
    "investigation_steps": ["Step 1"],
    "false_positives": ["FP 1"],
    "references": [],
    "tags": ["test"],
    "queries_content": {
      "splunk": "index=main | search test"
    }
  }'
```

#### Test 2: Aggiornare Playbook

```bash
curl -X PUT http://localhost:8000/api/playbooks/PB-T1234-001 \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Test Playbook",
    "severity": "critical"
  }'
```

#### Test 3: Gap Analysis

```bash
curl http://localhost:8000/api/mitre/gaps
```

#### Test 4: Eliminare Playbook

```bash
curl -X DELETE http://localhost:8000/api/playbooks/PB-T1234-001
```

---

## API Documentation

Dopo aver avviato il backend, visita:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

Documentazione completa di tutti gli endpoint con esempi interattivi.

---

## Troubleshooting

### Errore: "Playbook already exists"
- Verifica che l'ID sia univoco
- Controlla directory `playbooks/techniques/`

### Errore: "Invalid playbook format"
- Verifica schema JSON in `playbooks/schema.json`
- Controlla validazione Pydantic

### Errore: "AI service not available"
- Configura `GROQ_API_KEY` o `OPENAI_API_KEY` nel `.env`
- Suggerimenti AI funzionano solo se configurato

### Frontend non si connette al backend
- Verifica `VITE_API_URL` in `.env.local`
- Default: `http://localhost:8000/api`

---

## Prossimi Sviluppi

### Q1 2025
- [ ] Splunk App Integration
- [ ] Playbook Templates Library
- [ ] Bulk Import/Export
- [ ] Collaboration Features (Comments, Reviews)

### Q2 2025
- [ ] Advanced Analytics Dashboard
- [ ] Threat Intelligence Feeds Integration
- [ ] Automated Playbook Testing
- [ ] Multi-language Support

---

## Support & Feedback

Per domande o problemi:
- GitHub Issues: https://github.com/Johnny9802/threat_hunting_/issues
- Documentation: Questa guida
- Repository: https://github.com/Johnny9802/threat_hunting_

---

**Creato con** ❤️ **da Team Threat Hunting**
