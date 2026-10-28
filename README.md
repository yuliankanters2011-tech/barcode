# ScanBase — Synology, Docker Hub en NAS-scannerbrug

ScanBase is een Nederlandstalige voorraadwebapp met SQLite. Omdat de gewone Synology-containerwizard geen host-systeemmap zoals `/dev/bus/usb` kan koppelen, werkt deze variant met twee delen:

1. De webapp en database draaien in een gewone Docker-container.
2. Een klein Python-hulp-script draait op de Synology zelf als root, leest de HID-scanner en stuurt barcodes naar de webapp via `http://127.0.0.1:8081`.

De NAS-test heeft bevestigd dat de scanner ruwe HID-toetsrapporten doorgeeft; de geteste barcode was `90357558` met Tab als afsluittoets. De webapp ontvangt de helper-invoer via `/api/ingest`.

## Veiligheid

- Het hulp-script draait als root omdat het de USB-toetsenbordinterface kort loskoppelt en na afsluiten probeert terug te koppelen.
- ScanBase zelf heeft geen wachtwoord. Houd poort 8081 op je eigen netwerk; stel die niet open voor internet.
- Stop de eerdere handmatige USB-test met Ctrl+C voordat je de helper start.

## GitHub Actions → Docker Hub

De workflow staat in `.github/workflows/build-publish.yml` en bouwt/pusht de image naar `docker.io/ykdigital/scanbase:latest`.

1. Maak op Docker Hub een repository `scanbase`.
2. Maak een Docker Hub access token met Read & Write.
3. Voeg in GitHub bij **Settings → Secrets and variables → Actions** deze repository secrets toe:
   - `DOCKERHUB_USERNAME` = `ykdigital`
   - `DOCKERHUB_TOKEN` = je Docker Hub access token
4. Upload/push de bijgewerkte projectbestanden naar GitHub. Wacht tot **Actions** groen is; dan is de bijgewerkte image gepubliceerd.

## ScanBase-container maken via de gewone DSM-wizard (geen Project)

1. Zorg dat de nieuwe GitHub Actions-run is geslaagd, zodat `ykdigital/scanbase:latest` de bijgewerkte app bevat.
2. In Container Manager: haal de nieuwste image op en maak de container `ykdigital/scanbase:latest` aan.
3. Stel de poort in op NAS/lokaal `8081` → container `8080`, TCP.
4. Koppel de bestaande NAS-map `/volume1/docker/scanbase/data` aan `/data` met lezen/schrijven.
5. Zet, indien de wizard dit toont, `SCANNER_MODE` op `external`, `PORT` op `8080` en `DB_PATH` op `/data/scanbase.db`. Laat `PATH` ongemoeid.
6. Je hebt voor deze variant geen privileged-modus of `/dev`- en `/sys`-volumemounts nodig in de container.
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

De helper probeert bij het starten de vereiste HID-modules te laden als die nog niet geladen zijn. Hij luistert naar USB-ID `5131:2007`, leest Tab/Enter als einde van de barcode en stuurt de code naar de container via poort 8081. Na een scan hoort die in ScanBase te verschijnen.

Als de taak niet start, controleer dan de taakdetails en de containerlogs. Als de container meldt dat de helper-invoer niet aankomt, controleer dat de containerpoort op de NAS werkelijk `8081` is.
