# CSP degli script pubblicati

La workflow Pages esegue `build_csp.py` come ultima trasformazione HTML.
La policy meta viene inserita prima degli script, dopo la dichiarazione charset.
È una policy applicata dal browser, non report-only, e si combina per
intersezione con la CSP HTTP già configurata su Cloudflare: l'unsafe-inline
ancora presente nell'header non consente di aggirare la restrizione della meta.
Non è stato modificato l'account Cloudflare.

Gli script locali e i fornitori esplicitamente elencati sono consentiti.
I due blocchi inline già esistenti sono autorizzati per hash SHA-256 preciso.
Non sono autorizzati script inline arbitrari, eval, javascript: o attributi
onclick/onsubmit. I vecchi onsubmit delle demo vengono trasformati in listener
esterni equivalenti che impediscono l'invio del modulo.
JSON-LD e contenuti non vengono riscritti. CSS inline resta regolato dalla
policy Cloudflare esistente: questa modifica riguarda JavaScript.

Un nuovo script inline non approvato o un handler sconosciuto fanno fallire
la pubblicazione. Non aggiungere hash automaticamente senza rivedere il codice.
Per aggiornamenti legittimi, rivedere script e test, poi aggiornare APPROVED.
L'allowlist di domini e 'self' non equivale a una CSP strict-dynamic e non
protegge dalla compromissione degli account di pubblicazione o dei fornitori.
La meta non può impostare frame-ancestors: quella protezione resta nell'header.

Test: `python scripts/test_build_csp.py`.
Per collaudare la generazione usare una copia del sito, non la sorgente git.
Rollback: ripubblicare il branch backup/csp-scripts-20261024 o rimuovere lo step
CSP dalla workflow e ripubblicare. I sorgenti HTML originali sono invariati.
