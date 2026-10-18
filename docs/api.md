# API applicazioni — versione alfa

Base URL: `http://127.0.0.1:8765`. Il servizio deve essere avviato sullo stesso dispositivo. Il numero di porta può cambiare con `--port`.

La dashboard restituisce un token alla creazione di ogni delega. L'app deve inviarlo nell'header `Authorization: Bearer <token>` per tutte le richieste. Il token consente soltanto l'elenco e la lettura delle risorse della raccolta associata.

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
- `404`: risorsa inesistente o fuori dalla raccolta autorizzata.

Questi eventi vengono registrati nell'audit. Non utilizzare il token in URL, log o file di configurazione condivisi. La finalità indicata nella delega è dichiarativa; il server non può controllare cosa fa l'app con i byte già ricevuti.
