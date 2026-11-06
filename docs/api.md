# API applicazioni — v1

Base URL: `http://127.0.0.1:8765`. Il servizio deve essere avviato sullo stesso dispositivo. Il numero di porta può cambiare con `--port`.

La dashboard mostra un token alla creazione di ogni delega. L'app lo invia nell'header `Authorization: Bearer <token>`. Il token consente l'elenco e la lettura dei soli documenti selezionati in una raccolta. I file aggiunti in seguito e quelli ripristinati dal cestino richiedono una nuova delega.

## Elenco

```http
GET /v1/resources
Authorization: Bearer <token>
```

Risposta JSON: array di oggetti con `id`, `collection_id`, `name`, `size` e `created_at` (timestamp Unix in secondi). Non contiene percorsi del computer.

## Lettura

```http
GET /v1/resources/{id}/content
Authorization: Bearer <token>
```

Risposta: byte originali del documento, `application/octet-stream`. L'app usa `name` dall'elenco per riconoscere il file; l'endpoint contenuto non invia il nome nell'header di download.

## Errori

- `401`: token mancante o non valido.
- `403`: delega scaduta o revocata.
- `404`: risorsa assente, nel cestino o fuori dalla selezione autorizzata.
- `409`: il contenuto non è disponibile oppure l'integrità non è verificabile.
- `503`: archivio temporaneamente indisponibile, per esempio durante un errore di I/O.

Questi eventi vengono registrati nell'audit. Non utilizzare il token in URL, log o file di configurazione condivisi. La finalità indicata nella delega è dichiarativa; il server non può controllare cosa fa l'app con i byte già ricevuti.

## Per chi integra la dashboard

Gli endpoint `/admin` sono riservati all'utente del vault. La chiave amministrativa è distinta dai token applicativi. `POST /admin/grants` accetta `app_name`, `purpose`, `collection_id`, `duration_minutes` (intero tra 1 e 10080) e `resource_ids` (da 1 a 1000 ID attivi). Se omesso, `resource_ids` seleziona i documenti attivi al momento della richiesta, entro il limite di 1000. `GET /admin/audit` restituisce `items` e `next_before` per la pagina successiva. L'API pubblica per le app rimane `/v1`.
