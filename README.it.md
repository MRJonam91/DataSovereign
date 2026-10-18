# DataSovereign α

[English](README.md) · [Sicurezza](SECURITY.md) · [API](docs/api.md)

![Diagramma animato di import locale, delega circoscritta, lettura e revoca](docs/assets/demo.svg)

DataSovereign permette di importare documenti in un vault locale e concedere a un'app accesso in sola lettura a una raccolta selezionata, con scadenza e revoca.

L'alfa funziona su Windows, per un solo utente, sul proprio computer. I documenti importati sono copie cifrate per l'account Windows corrente. Le app autorizzate accedono solo tramite API su `127.0.0.1`.

## Avvio

Richiede Python 3.11 o successivo. Dalla cartella del progetto:

```powershell
python -m pip install -e .
python -m datasovereign serve
```

Il comando mostra un URL locale con una chiave di amministrazione temporanea. Aprilo nel browser, importa file in una raccolta, crea una delega e copia il token mostrato una sola volta all'applicazione. Alla chiusura del server la chiave di amministrazione scade. I dati restano in `%LOCALAPPDATA%\DataSovereign\alpha` salvo `--data-dir`.

## API per le applicazioni

Usa il token della delega nell'header `Authorization: Bearer <token>`:

```powershell
curl.exe -H "Authorization: Bearer TOKEN" http://127.0.0.1:8765/v1/resources
curl.exe -H "Authorization: Bearer TOKEN" http://127.0.0.1:8765/v1/resources/RESOURCE_ID/content --output documento.bin
```

Una delega consente solo `list` e `read` nella raccolta scelta, fino alla scadenza o alla revoca. L'API non accetta percorsi del filesystem.

## Esportazione

La dashboard offre un export ZIP con documenti decifrati e JSON di raccolte, deleghe senza token e audit. Il file ZIP è in chiaro: conservalo in un luogo adeguato e cancellalo quando non serve.

## Limiti dell'alfa

- Le copie originali importate restano dove si trovavano.
- Nomi dei file, raccolte, deleghe e audit sono in SQLite in chiaro; il contenuto dei file è protetto con Windows DPAPI.
- La cifratura è legata all'account Windows: un altro account o una nuova installazione Windows non può decifrare il vault senza una strategia di migrazione futura.
- Un'app che ha già scaricato dati può conservarli dopo la revoca.
- Il controllo vale per le richieste alla API DataSovereign. Un programma avviato con gli stessi permessi Windows dell'utente può leggere direttamente i file originali o tentare di accedere al vault. Per l'agente AI usa un ambiente isolato o un'integrazione che riceve solo il token API.
- La finalità è dichiarata e registrata, ma il software non può verificare per quale scopo l'app usa una copia ricevuta.
- Un programma malevolo in esecuzione con lo stesso account Windows può agire a nome dell'utente.
- L'audit è append-only nell'applicazione, non è a prova di alterazione da parte di un amministratore del dispositivo.
- Dimensione massima per file: 10 MiB. Dimensione massima del vault esportabile: 50 MiB.

Vedi [API](docs/api.md) e [modello delle minacce](docs/security/alpha-threat-model.md).

## Licenza e supporto

Codice: [AGPL-3.0-only](LICENSE). Vedi [dettagli sulle licenze](LICENSING.md), [condizioni per contribuire](CONTRIBUTING.md) e [supporto](SUPPORT.md). Le richieste di licenza commerciale sono descritte in [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
