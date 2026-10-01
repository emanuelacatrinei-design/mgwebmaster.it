# MG Webmaster Site Check API

Backend ridotto per la pagina pubblica MG Site Check.

- massimo 5 pagine HTML;
- nessun database;
- nessun archivio delle scansioni;
- nessun accesso a Search Console, Analytics, database keyword, AI locale o competitor;
- protezioni SSRF: blocco IP privati/localhost, porte 80/443, redirect validati;
- limite 2 MB per pagina;
- output sintetico per il frontend pubblico.

## Avvio locale

```bash
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 8080 --no-access-log
```

Health check: `GET /health`
Scansione: `POST /v1/scan`

La pagina pubblica resta noindex fino al completamento del deploy e delle protezioni Cloudflare/Turnstile.

Nota privacy: il codice applicativo non salva scansioni o report, ma CDN, hosting e reverse proxy possono produrre log tecnici. La configurazione reale e la Privacy Policy devono descrivere il trattamento effettivo.
