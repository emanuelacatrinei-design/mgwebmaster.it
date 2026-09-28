# Demo navigabili dei template MG Webmaster

La vetrina presenta siti completi, esplorabili prima di chiedere la personalizzazione. Questa regola vale anche per ogni caricamento futuro.

## Struttura

- `template/demos.json`: registro dei concept, provenienza degli archivi originali (SHA-256) e pagine nelle due lingue.
- `template/<slug>/demo/index.html`: visualizzatore italiano.
- `ro/template/<slug>/demo/index.html`: visualizzatore rumeno.
- `.../demo/site/*.html`: pagine effettive e navigazione interna nella rispettiva lingua.
- `template/demo-assets/<slug>/`: fotografie WebP, grafica e CSS propri del concept, condivisi solo quando non contengono testo da tradurre.
- `template/demo-shared/`: visualizzatore, comportamenti accessibili e font locali. Le immagini SVG con testo hanno file IT e RO distinti.

Il codice pubblicato è il sito dimostrativo. Gli archivi originali, gli eseguibili di avvio e i file di lavorazione non vanno caricati nella vetrina. HTML, CSS e immagini visualizzati nel browser restano tecnicamente copiabili; il visualizzatore non è un sistema DRM.

## Aggiungere un template

1. Creare e verificare un branch di backup del `main` corrente.
2. Partire dai file completi del progetto approvato. Conservare struttura, immagini originali autorizzate e identità del design. Non usare immagini o kit Elementor come prodotto finale.
3. Preparare tutte le pagine IT e RO. Tradurre menu, titoli, paragrafi, ALT e messaggi; controllare anche testo nelle immagini. Usare recapiti chiaramente dimostrativi. I luoghi reali dei concept restano quelli originali.
4. Inserire gli asset leggeri in `demo-assets/<slug>/`. Ogni foto raster deve essere WebP, con dimensioni HTML, `decoding="async"` e caricamento lazy fuori dalla prima schermata. Non duplicare gli stessi asset per le due lingue.
5. Preparare i due visualizzatori usando `viewer.css` e `viewer.js`, tre pulsanti `data-device`, `#demo-page` e `.demo-frame`. La select elenca esclusivamente le pagine della demo. Il parametro `?pagina=...` deve essere validato contro quell’elenco.
6. Includere `runtime.css` e `runtime.js` nelle pagine. I moduli devono avere `data-demo-form`, nessun endpoint di invio e pulsanti submit inizialmente `disabled`: lo script li abilita soltanto dopo avere registrato la gestione locale. Non collegare prenotazioni o pagamenti reali. Conservare l’avviso dimostrativo.
7. Impostare `lang` e `noindex,follow` su visualizzatore e pagine demo. Non aggiungere queste pagine alla sitemap. Le pagine di vendita mantengono canonical, hreflang e dati strutturati esistenti.
8. Aggiungere la voce in `demos.json`, con pagine IT/RO effettive. Collegare le due card e i due dettagli a `/demo/`; le immagini nel catalogo rimangono miniature, non sono l’unica anteprima.
9. Eseguire `python scripts/check_template_demos.py`. Il controllo fallisce per demo mancanti, riferimenti inesistenti, lingua dichiarata errata, immagini vuote, dipendenze remote e moduli collegati a un invio reale. Non rimuovere il controllo dal workflow Pages.
10. Verificare nel browser entrambe le lingue: desktop, tablet, mobile; menu aperto/chiuso, pagine interne, ritorno al catalogo, cambio lingua, gallerie, tastiera e moduli di prova. Dopo il deploy verificare HTTP 200 e visualizzazione reale delle immagini. I controlli automatici non sostituiscono la revisione visiva e linguistica.

## Contenuti dimostrativi

Le attività illustrate, le persone, le recensioni e i risultati numerici sono esempi di impaginazione, non clienti o risultati di MG Webmaster. Gli avvisi della demo devono rimanere visibili. Le fonti originali dei dodici concept sono registrate nel manifest; gli archivi rimangono separati dalla pubblicazione.

Font Cormorant Garamond, Inter e Montserrat distribuiti localmente; licenze OFL nella cartella `demo-shared/fonts/`.
