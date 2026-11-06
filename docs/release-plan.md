# DataSovereign 1.0

La 1.0 consegna il vault locale a un solo utente Windows. Il percorso di accettazione è importare una copia, concedere accesso a documenti scelti, verificare letture e revoca, consultare l'audit e recuperare un backup in un vault vuoto.

| Passaggio | Implementazione | Verifica |
| --- | --- | --- |
| Upgrade e integrità | Migrazione dello schema, copia del database precedente, checksum | Aprire un vault alfa, migrare e riaprire senza perdere documenti o ampliare accessi |
| Consenso e ciclo di vita | Scope fisso, transazioni SQLite, cestino e ripristino | Intercalare due connessioni e verificare che un documento ripristinato richieda nuova autorizzazione |
| Backup e ripristino | Archivio DPAPI con verifica preventiva e rollback | Provare archivio valido, manomesso e destinazione occupata |
| Dashboard e CLI | Selettore filtrabile, audit paginato, verifica del vault | Completare import, delega, revoca, backup e ripristino da browser |
| Distribuzione | Versione 1.0.0, documentazione bilingue, wheel e sdist | Eseguire test Windows, controllare pacchetti e cronologia pubblicabile, verificare GitHub Actions e release |

## Sviluppo dopo la 1.0

1. **Manutenzione.** Correggere regressioni su migrazione, backup e integrazioni, preservando il contratto pubblico `/v1`.
2. **Recupero portabile.** Valutare un formato con chiave gestita dall'utente e test di recupero tra account prima di promettere migrazione cifrata tra dispositivi.
3. **Isolamento dei client.** Documentare e verificare configurazioni con identità Windows distinte prima di estendere il confine di fiducia.
4. **Identità applicativa.** Valutare opzioni di interoperabilità come integrazioni facoltative.
