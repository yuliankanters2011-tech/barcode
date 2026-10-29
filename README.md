# ScanBase — Synology, Docker Hub en scannerbrug

ScanBase is een Nederlandstalige voorraadwebapp met SQLite. De webapp draait in een gewone Docker-container. Een klein Python-hulp-script draait op de Synology zelf als root, leest de HZTZ HID-scanner en stuurt barcodes naar de webapp via `http://127.0.0.1:8081`.

## Wat de app doet

- **Mijn voorraad:** jouw persoonlijke artikelen, locaties en notities. Deze database staat los van de online catalogus.
- **Algemene database:** bij een onbekende scan zoekt ScanBase automatisch online. Je kunt ook zelf een barcode invoeren in deze tab. Resultaten worden apart lokaal gecachet en verschijnen bij “Recent online opgezocht”.
- De online lookup probeert UPCitemdb voor algemene UPC/EAN/GTIN-producten. Als daar geen match is (of UPCitemdb de barcode als film markeert), wordt ook UPCMDB geraadpleegd: een publieke exacte barcodelookup voor DVD-, Blu-ray- en 4K-uitgaven. Voor muziek-cd's probeert hij MusicBrainz op de exacte barcode. Voor Nederlandse ISBN's met prefix 97890 of 97894 zoekt hij ook de openbare KB/Nederlandse Bibliografie (NBT), zonder API-sleutel. Overige ISBN's, waaronder schoolboeken, worden via Google Books en daarna Open Library gezocht. De dekking verschilt per editie en is nooit volledig; controleer de bron en pas gegevens zo nodig aan. UPCitemdbs gratis Explorer biedt maximaal 100 verzoeken per dag; ScanBase bewaart gevonden én niet-gevonden barcodes lokaal 24 uur om herhaalde aanvragen te beperken; oude cachemissers worden na deze provideruitbreiding één keer opnieuw opgezocht. MusicBrainz wordt maximaal één keer per seconde bevraagd. [UPCitemdb API](https://www.upcitemdb.com/api/) · [UPCMDB demo](https://upcmdb.com/demo) · [MusicBrainz barcode search](https://musicbrainz.org/doc/MusicBrainz_API/Search) · [Google Books API](https://developers.google.com/books/docs/v1/using) · [OFF API](https://openfoodfacts.github.io/openfoodfacts-server/api/tutorial-off-api/) · [Open Products Facts API](https://world.openproductsfacts.org/data) · [Open Library API](https://openlibrary.org/developers/api) · [KB/NBT SPARQL](https://data.bibliotheken.nl/sparql)
- Productdekking is **niet compleet**. Als geen openbare catalogus het product kent, kun je het zelf benoemen en opslaan in je persoonlijke voorraad.
- Als UPCitemdb aanbiedersinformatie heeft, toont ScanBase ook winkels en mogelijke prijzen. Die gegevens kunnen verouderd zijn, dus controleer ze bij de winkel. Zonder API-sleutels biedt de app zoeklinks naar Google Shopping, Google, Bol.com, Amazon.nl, Marktplaats, De Slegte, Bookmatch, Bruna en Discogs. De Slegte, Bookmatch en Bruna openen een Google-zoekopdracht die op die winkel is gericht. Het zijn zoekpagina's; de app leest Google-resultaten niet automatisch uit en garandeert geen actuele prijs of voorraad. Automatische Google-resultaten of Bol-aanbiedingen vereisen externe API-toegang en credentials.
- Na een scan van een artikel dat al in jouw voorraad staat toont ScanBase de opgeslagen naam en locatie. Bij een nieuw online resultaat vraagt de app eerst of je het aan Mijn voorraad wilt toevoegen. Je kunt de naam aanpassen en een bestaande locatie kiezen, een nieuwe locatie invoeren of **Geen locatie** selecteren. Bij een online misser kun je het artikel handmatig benoemen.
- De knop **Online zoeken** staat rechtsboven in de kop. Online resultaten blijven in een aparte catalogus/cache; alleen na jouw bevestiging worden ze gekopieerd naar Mijn voorraad.

## Veiligheid

- De scannerbrug draait als root omdat die de USB-toetsenbordinterface tijdelijk loskoppelt en bij afsluiten weer probeert aan te koppelen.
- ScanBase zelf heeft geen wachtwoord. Houd poort 8081 op je eigen netwerk; stel die niet open voor internet.
- Stop de eerdere handmatige USB-test met Ctrl+C voordat je de scannerbrug start.

## GitHub Actions → Docker Hub

De workflow staat in `.github/workflows/build-publish.yml` en bouwt/pusht de image naar `docker.io/ykdigital/scanbase:latest`.

1. Maak op Docker Hub een repository `scanbase`.
2. Maak een Docker Hub access token met Read & Write.
3. Voeg in GitHub bij **Settings → Secrets and variables → Actions** deze repository secrets toe:
   - `DOCKERHUB_USERNAME` = `ykdigital`
   - `DOCKERHUB_TOKEN` = je Docker Hub access token
4. Push de bijgewerkte projectbestanden naar GitHub. Wacht tot **Actions** groen is; dan is de nieuwe image gepubliceerd.

## ScanBase-container maken via de gewone DSM-wizard (geen Project)

1. Zorg dat de nieuwste GitHub Actions-run geslaagd is, zodat `ykdigital/scanbase:latest` de bijgewerkte app bevat.
2. Haal in Container Manager de nieuwste image op en maak een container van `ykdigital/scanbase:latest`.
3. Stel de poort in op NAS/lokaal `8081` → container `8080`, TCP.
4. Koppel de NAS-map `/volume1/docker/scanbase/data` aan `/data` met lezen/schrijven.
5. Stel, indien de wizard dit toont, `SCANNER_MODE=external`, `PORT=8080` en `DB_PATH=/data/scanbase.db` in. Laat `PATH` ongemoeid.
6. Voor deze variant zijn geen privileged-modus en geen `/dev`- of `/sys`-volumemounts nodig in de container.
7. Start de container. De database blijft in `/volume1/docker/scanbase/data/scanbase.db`.

Open daarna `http://IP-VAN-JE-NAS:8081`.

## NAS-scannerbrug instellen via DSM Taakplanner

Kopieer `usb_scan_bridge.py` naar `/volume1/docker/scanbase/usb_scan_bridge.py`. Maak daarna een taak:

1. Open **Configuratiescherm → Taakplanner → Maken → Geactiveerde taak → Door gebruiker gedefinieerd script**.
2. Kies als gebruiker **root** en als gebeurtenis **Opstarten**.
3. Vul bij het gebruikersscript in:

```sh
python3 /volume1/docker/scanbase/usb_scan_bridge.py
```

4. Sla de taak op en voer hem één keer handmatig uit om te testen. Laat de scanner aangesloten.

De helper probeert bij het starten de HID-modules te laden als die nog niet geladen zijn. Hij luistert naar USB-ID `5131:2007`, herkent Tab/Enter als barcode-einde en stuurt de code via poort 8081 naar de webapp. Na een scan hoort de app de code te tonen of online op te zoeken.
