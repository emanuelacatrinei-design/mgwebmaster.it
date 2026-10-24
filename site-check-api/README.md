# MG Webmaster Site Check API

Backend pubblico ridotto, versione 0.2.0, per le pagine di analisi IT e RO.
Non esegue JavaScript del sito analizzato e non conserva scansioni o report.
Nessun accesso a Search Console, Analytics, database keyword o motore privato.

## Protezioni e limiti

- Solo HTTP/HTTPS e porte 80/443; niente credenziali negli URL.
- Verifica di tutti gli indirizzi DNS restituiti; rifiuto delle destinazioni non
  pubbliche, IPv4/IPv6, indirizzi locali e meccanismi di traduzione IPv6.
- Connessione direttamente all'IP verificato, conservando Host, SNI e controllo
  del certificato TLS del dominio. Nessuna seconda risoluzione del dominio fra
  controllo e connessione. Nessun proxy ricavato dalle variabili di ambiente.
- Ogni redirect viene risolto, verificato e collegato nuovamente; massimo 5.
- Massimo 5 pagine HTML, 2 MB per pagina, 12 MB complessivi e 36 richieste di rete.
- Richiesta di risposte non compresse; risposte compresse non conformi rifiutate
  per evitare decompressioni non limitate. Nessun cookie condiviso fra scansioni.
- Ogni analisi usa un processo separato, terminato dal processo principale dopo
  45 secondi, anche se DNS, lettura o parsing restano bloccati.
- Su Linux/Render: limite per processo figlio di 192 MiB di spazio di indirizzi
  e 40 secondi di CPU. Il processo separato non è una sandbox di rete.
- Due richieste di scansione contemporanee al massimo. La route `/health`
  rimane disponibile mentre lavorano i processi figli.
- Corpo delle richieste limitato a 8 KiB anche senza Content-Length, invio
  massimo 10 secondi; richieste compresse rifiutate.
- 5 tentativi per identità di rete ogni 10 minuti; quota globale di 20 scansioni
  verificate ogni 10 minuti. I token anti-bot non validi non consumano la quota
  delle scansioni verificate. Risposte 429 con Retry-After quando applicabile.
- Turnstile verificato sul server: successo, hostname MG Webmaster e azione
  `site_scan`. Assenza della chiave segreta: scansione rifiutata. Il frontend
  rinnova il widget dopo ogni tentativo perché i token sono monouso.
- Nessuna documentazione API pubblica; risposte non memorizzabili in cache.
- I log applicativi riportano categoria/stato e numero di pagine, non URL,
  token, indirizzi IP o contenuti analizzati. Gli errori pubblici non espongono
  eccezioni interne. Messaggi di errore IT/RO.

## Esecuzione

```bash
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8080 --no-access-log --no-proxy-headers --workers 1
```

Produzione: `0.0.0.0` e porta `$PORT` fornita da Render. Conservare **un solo
worker e una sola istanza**: quote e semaforo sono in memoria, si azzerano al
riavvio e non sono condivisi fra processi/istanze. Prima di scalare, usare quote
condivise e un limite globale dei job.

Variabili:

- `TURNSTILE_SECRET`: chiave reale del widget, solo nell'ambiente Render.
- `MG_SITE_ORIGIN`: `https://www.mgwebmaster.it`.
- `FORWARDED_ALLOW_IPS`: stringa vuota; impedisce a Uvicorn di sostituire il peer
  con informazioni provenienti da intestazioni non verificate, anche se si
  mantiene il vecchio comando di avvio senza `--no-proxy-headers`.
- `WEB_CONCURRENCY`: `1`, per il comando di avvio esistente.
- `MG_TRUSTED_PROXY_CIDRS`: vuota per impostazione predefinita. Non impostarla
  a `0.0.0.0/0` o `::/0`. Aggiungere soltanto reti di proxy effettivamente
  verificati che aggiungono/sovrascrivono correttamente X-Forwarded-For.

Per impostazione predefinita il limite usa il peer della connessione. Dietro
un proxy più visitatori possono quindi condividere lo stesso limite: è una
scelta conservativa finché la catena reale di proxy non è verificata.
`CF-Connecting-IP` non viene accettato ciecamente. CORS non è autenticazione:
le protezioni restano attive anche contattando direttamente l'URL Render.

Il widget Turnstile delle pagine IT/RO deve avere `data-action="site_scan"`.
L'account Cloudflare deve limitarlo ai domini MG Webmaster previsti.

Health check: `GET /health`, con versione applicativa.
Scansione: `POST /v1/scan`, JSON (anche con Content-Type text/plain per il
frontend pubblico): `url`, `authorized: true`, `turnstile_token`, `language`
opzionale (`it` o `ro`).

## Test e manutenzione

Dalla radice del repository:

```bash
python -m pip install -r site-check-api/requirements.txt pytest==9.1.1 httpx==0.28.1 pip-audit
python -m pytest -q tests/site_check
python -m pip_audit --progress-spinner off -r site-check-api/requirements.txt
node --check site-check.js
```

I test usano fixture locali per risoluzione DNS, redirect, TLS e Turnstile;
non attaccano servizi esterni. Verificano anche arresto del processo bloccato,
concorrenza, dimensioni, limiti e contratto del report. La workflow
`site-check-security.yml` esegue test e controllo delle dipendenze su GitHub.
Gli aggiornamenti delle versioni fissate in requirements.txt vanno riprovati
e verificati contro gli avvisi di sicurezza prima della pubblicazione.

## Controlli operativi

Dopo ogni deploy verificare la versione di `/health`, una scansione autorizzata
normale e il rifiuto di richieste senza token anche sull'URL Render diretto.
Non disattivare Turnstile in produzione per effettuare test.

La protezione di rete in uscita, con blocco delle reti interne e dei servizi
metadata a livello infrastrutturale, resta una difesa aggiuntiva da predisporre
con le funzioni effettivamente disponibili sull'hosting. Il solo codice non
equivale a un firewall di uscita né garantisce assenza di vulnerabilità.

La configurazione reale di CDN, hosting e reverse proxy può produrre log
tecnici propri. Privacy Policy e tempi di conservazione devono descrivere il
trattamento effettivo.
