# Verifiche di rilascio / Release checks

1. Eseguire la suite su Windows con Python 3.11 e 3.14. / Run the Windows suite on Python 3.11 and 3.14.
2. Provare il percorso importazione, delega, revoca, backup e ripristino con dati sintetici su desktop e mobile. / Exercise import, delegation, revocation, backup and restore with synthetic data at desktop and mobile widths.
3. Costruire wheel e sorgenti dal commit di rilascio, ispezionarne il contenuto e verificare il wheel installato. / Build wheel and source archive from the release commit, inspect contents and verify the installed wheel.
4. Controllare che cronologia pubblicabile e pacchetti contengano soltanto file autorizzati. / Review publishable history and packages for authorized files.
5. Verificare la CI su `main`, il tag, gli hash degli allegati e la visibilità pubblica. / Verify CI on `main`, tag, asset hashes and public visibility.
