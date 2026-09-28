# Regole di manutenzione

- Prima di modificare il sito, creare e verificare un backup del repository allo stato corrente (per esempio un branch di ripristino sul commit di partenza).
- Ogni controllo su una pagina italiana deve includere la corrispondente pagina rumena. Le correzioni comuni vanno verificate su entrambe le lingue.
- Per le modifiche responsive, controllare header, menu e contenuto ai breakpoint mobile, tablet e desktop su entrambe le pagine. Distinguere i test del codice dalle verifiche visive effettivamente eseguite nel browser.
- Mantenere testi, immagini e metadati specifici di ciascuna lingua, salvo modifiche espressamente richieste.
- I testi rumeni devono adattare fedelmente quelli italiani: stessi contenuti e finalità, senza riassunti che omettano sezioni. Usare un rumeno naturale, comprensibile e con pochi tecnicismi inutili.
- Il pubblico e la SEO locale delle pagine rumene sono in Romania. La sede reale a Perugia e i luoghi dei progetti restano quelli effettivi; non inventare sedi o clienti rumeni.
- Usare “motori di ricerca” / “motoare de căutare” per la ricerca in generale; conservare i nomi specifici di Google Maps, Google Ads, Google Business Profile, Analytics e Search Console quando pertinenti.
- Le immagini esistenti devono conservare file, ordine e collocazione strutturale, salvo richiesta esplicita dell’utente.

## Regola permanente per i template

- Ogni template attuale e futuro deve avere una demo HTML/CSS/JS realmente navigabile, derivata dal proprio progetto originale, con pagine interne, menu e layout responsive. Una fotografia o uno screenshot non costituiscono una demo.
- Pubblicare e verificare insieme le versioni italiana e rumena: testi, navigazione, ALT, messaggi dei moduli e immagini contenenti testo devono corrispondere alla lingua scelta. Conservare nomi dei concept e luoghi reali; distinguere chiaramente dati e attività dimostrativi.
- Usare il visualizzatore condiviso con scelta desktop/tablet/mobile, ritorno al catalogo e richiesta del design. Collegare le anteprime delle card e le pagine di dettaglio direttamente alla demo. Registrare ogni nuova demo in `template/demos.json` e seguire `template/README.md`.
- Conservare la grafica distinta di ogni progetto. Non ricostruire tutti i template su un unico layout generico. Non pubblicare archivi ZIP, file di lavoro o kit Elementor; usare soltanto gli asset originali autorizzati necessari alla demo.
- I moduli delle demo non devono inviare né conservare dati. Le pagine demo devono avere `noindex,follow`; le pagine commerciali del catalogo mantengono SEO, canonical e hreflang.
- Non promettere protezioni impossibili contro screenshot o copia del contenuto mostrato dal browser. Non bloccare tasto destro, selezione o scorciatoie: peggiorano accessibilità e navigazione senza proteggere il codice.
- Prima di pubblicare eseguire `python scripts/check_template_demos.py`, verificare visivamente desktop/tablet/mobile in entrambe le lingue e provare menu, pagine interne, gallerie e moduli. Il workflow Pages deve mantenere attivo questo controllo; un template senza demo completa non può essere pubblicato.
