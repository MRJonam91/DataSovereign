# Modello delle minacce della 1.0

DataSovereign controlla le letture **attraverso la sua API locale**. Ogni token autorizza un insieme fisso di documenti con scadenza e revoca. Il server verifica la delega a ogni richiesta e registra le decisioni.

## Protezioni implementate

- I contenuti copiati nel vault sono protetti con Windows DPAPI nell'ambito dell'utente corrente.
- L'API ascolta solo su `127.0.0.1` e accetta host loopback.
- Gli endpoint admin richiedono una chiave casuale che dura quanto il processo; gli endpoint per app richiedono un token di delega.
- I token delle app sono memorizzati come hash e mostrati solo alla creazione.
- Nessuna risorsa è selezionabile via path del filesystem; gli ID delle risorse sono casuali.
- Le risposte dichiarano `no-store`, limitano le origini per la dashboard e non consentono CORS.
- I checksum rilevano documenti mancanti, non decifrabili o sostituiti. Il cestino rimuove il documento dalle deleghe esistenti.
- Il backup cifra e autentica il manifest con DPAPI. Il ripristino verifica contenuti e metadati, richiede un vault vuoto e recupera le deleghe come revocate.

## Minacce non risolte

- Un'app locale eseguita con i permessi dell'utente può leggere file originali o provare a usare direttamente DPAPI. La delega API non è un sandbox del sistema operativo.
- Un'app può conservare e diffondere dati già scaricati anche dopo la revoca.
- La finalità dichiarata non è enforceable dopo la consegna dei dati.
- Nomi dei file, raccolte, deleghe e audit restano in chiaro nel database.
- Un amministratore del dispositivo può modificare o cancellare il database di audit.
- Il backup DPAPI è legato all'account Windows e al dispositivo. Conservare una copia indipendente dei documenti necessari dopo un cambio di account, dispositivo o reinstallazione.
- Non è stata eseguita una security review indipendente né un penetration test.

Per provare il caso d'uso con un agente AI, usare documenti di prova e un agente configurato per consultare solo gli endpoint DataSovereign. Non concedere all'agente accesso diretto alle cartelle Windows che si vogliono tenere escluse.
