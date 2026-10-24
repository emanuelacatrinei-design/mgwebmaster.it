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


## Controlli passivi PHP e sicurezza — 0.3.0

Il report aggiunge `php`: versioni dichiarate negli header `Server`/`X-Powered-By`,
origine dell’osservazione, stato, fonti ufficiali e data di revisione delle regole.
Cookie PHPSESSID e URL `.php` sono soltanto indizi senza versione; nessun banner
significa **non verificabile**, mai PHP assente o sito sicuro. Non vengono cercati
`phpinfo.php`, pannelli, backup o file di configurazione. Nessun payload di exploit
viene inviato e il numero massimo di richieste non aumenta.

Le soglie del 21 ottobre 2026 (8.2.35, 8.3.36, 8.4.27, 8.5.12) riguardano
CVE-2026-109618 / CVE-2026-109619. Un banner precedente genera un rischio
**potenziale**, con verifica delle patch dell’hosting: i vendor possono applicare
backport senza cambiare la versione. Un banner successivo raggiunge soltanto
quelle soglie, non certifica la sicurezza. CVE-2026-115560 dipende anche dalla
configurazione e dal codice applicativo: questo controllo non la verifica.

Le regole sono locali, revisionate il 24 ottobre 2026: dopo 30 giorni il report
segnala che devono essere aggiornate. Non esiste ancora un feed CVE automatico.
Le date di fine supporto dei rami noti vengono valutate alla data della scansione.
Rami nuovi, versioni incomplete e prerelease richiedono verifica manuale.

Ulteriori osservazioni sulle sole risposte già scaricate: script/iframe HTTP in
pagine HTTPS, moduli con destinazione HTTP, attributi dei cookie dal nome
riconducibile a sessioni e testo compatibile con errori PHP. Non vengono salvati
né restituiti valori dei cookie o dettagli degli errori. Questi sono segnali da
verificare, non dimostrazioni di intrusione o test di sfruttabilità. Le nuove
segnalazioni e il riquadro PHP sono localizzati IT/RO e inclusi nell’export TXT.

Fonti: https://www.php.net/archive/2026.php#2026-10-21-5 ;
https://www.php.net/supported-versions.php ;
https://cert.europa.eu/publications/security-advisories/2026-018/


## Aggiornamento automatico avvisi e analisi CSP — 0.4.0

Il backend avvia un thread indipendente all’accensione e ricontrolla ogni sei ore
l’API pubblica degli avvisi del repository ufficiale `php/php-src`. Non richiede
chiavi API e non comunica alla fonte gli URL scansionati. Su Render gratuito il
controllo periodico opera mentre il servizio è attivo; dopo un riavvio riparte
automaticamente. Non è un servizio di monitoraggio continuo o di notifica.

Fonte fissa HTTPS, redirect e proxy d’ambiente disabilitati, timeout e limite
4 MiB. Conserva solo ID, gravità, intervalli di versione e URL ufficiali; scarta
le descrizioni, che possono contenere prove di attacco. Cache locale atomica
con permessi privati; un errore non sostituisce l’ultima copia valida. Non cambia
le protezioni SSRF né i budget delle scansioni. `/health.php_advisories` espone
stato, conteggio e data dell’ultimo download riuscito, senza dati dei clienti.

La prima pagina comprende al massimo 100 avvisi pubblicati. Se esiste una pagina
successiva, la copertura è dichiarata parziale. Mancanza di dati o ultimo download
oltre 24 ore vengono indicati nel report; rimangono anche le regole incorporate.
Il confronto supporta intervalli numerici semplici, congiunzioni e alternative;
le forme sconosciute richiedono verifica manuale. Le righe PHP del tipo `< X.Y.Z`
sono trattate come specifiche del ramo X.Y per evitare falsi positivi tra rami.
La corrispondenza resta potenziale: non conferma prerequisiti, estensioni attive,
patch del fornitore o sfruttabilità. Un avviso non ancora pubblicato nella fonte
non può essere rilevato automaticamente. Le date di supporto e le eccezioni
specifiche richiedono ancora manutenzione delle regole incorporate.

La CSP considera header HTTP e meta in head, cumulativamente. Ignora Report-Only
e le direttive non applicabili nelle meta, rispetta la prima direttiva duplicata
e analizza il fallback script-src-elem/attr → script-src → default-src. Verifica
inline/eventi, eval, fonti eccessivamente ampie, object-src e base-uri. Considera
nonce/hash, strict-dynamic e sandbox per evitare falsi positivi comuni. Le policy
meta possono arrivare dopo risorse già caricate: il controllo non ricostruisce
l’esecuzione del browser. Non valida ogni sintassi o ogni combinazione CSP3 e non
è un test di XSS o una certificazione. I nuovi messaggi sono disponibili IT/RO.

Riferimenti: https://docs.github.com/en/rest/security-advisories/repository-advisories
; https://www.w3.org/TR/CSP/
