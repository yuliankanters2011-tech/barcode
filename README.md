# ScanBase voor Synology + GitHub Actions

ScanBase is een kleine Nederlandstalige voorraadwebapp met SQLite. De GitHub Actions-workflow bouwt bij iedere push automatisch een Docker-image en publiceert die bij GitHub Container Registry (GHCR). De app gebruikt geen pip-pakketten.

## Scanner en veiligheid

- De USB-lezer gebruikt Linux usbfs rechtstreeks. De HID-rapporten van de HZTZ-scanner zijn op de NAS getest; de getoonde reeks kwam overeen met `90357558` plus Tab.
- De container krijgt `privileged`-rechten, toegang tot `/dev/bus/usb` en schrijft tijdelijk naar de `usbhid`-driverinterface om alleen de toetsenbordinterface van de scanner los en weer vast te koppelen. Gebruik dit uitsluitend op een vertrouwd thuisnetwerk.
- De webapp heeft geen wachtwoord. Stel poort 8080 niet rechtstreeks open voor internet.
- De USB-toegang vanuit Docker moet nog op jouw Synology worden bevestigd. Als de container de USB- of sysfs-mount weigert, plak dan de exacte Container Manager-log.

## De projectmap naar GitHub uploaden

1. Pak `scanbase-docker.zip` uit op je Windows-pc.
2. Installeer/open **GitHub Desktop** en meld je aan bij GitHub.
3. Kies **File → Add local repository** en selecteer de uitgepakte map `scanbase-docker`. Als GitHub Desktop zegt dat het nog geen repository is, kies **create a repository** en selecteer die map.
4. Kies **Publish repository**. De map moet als repository-root de bestanden `Dockerfile`, `app.py`, `docker-compose.yml` en de map `.github/workflows/` bevatten.
5. Wacht op de workflow onder het tabblad **Actions**. Die bouwt de image; bij een push naar de standaardbranch publiceert hij de tag `latest` naar GHCR.

Je hoeft geen GitHub Actions-secret aan te maken: de workflow gebruikt `GITHUB_TOKEN`.

## Image gebruiken op de Synology

Na de eerste geslaagde Actions-run:

1. Open de GHCR-package die bij je GitHub-repository hoort. GitHub maakt de eerste package vaak privé. Maak hem openbaar als je de image op de NAS zonder login wilt ophalen. Wil je hem privé houden, dan moet je op DSM eerst bij `ghcr.io` inloggen met een GitHub-token met `read:packages`.
2. Open `docker-compose.ghcr.yml` en vervang `YOUR_GITHUB_NAME/YOUR_REPOSITORY` door bijvoorbeeld `yulian-aleen/scanbase` (gebruik de eigen account- en repositorynaam).
3. Pak de projectmap uit in een gedeelde map op de NAS. Zorg dat `data/` naast de compose-bestanden staat.
4. Stop eventuele USB-testscript(s) op de NAS met **Ctrl+C** en controleer dat `usbhid` opnieuw aan de scanner is gekoppeld. Laat de scanner aangesloten.
5. Open **Container Manager → Project → Maken**, kies de projectmap en selecteer `docker-compose.ghcr.yml`. Start het project.
6. Open `http://IP-VAN-JE-NAS:8080`.

De database blijft bewaard in `data/scanbase.db`, ook wanneer de container opnieuw wordt gemaakt. Maak daarvan af en toe een reservekopie.

## Lokaal bouwen op de NAS

De gewone `docker-compose.yml` bouwt dezelfde app lokaal vanaf `Dockerfile` en `app.py`. In Container Manager kun je die compose-file kiezen in plaats van de GHCR-variant.

## Handmatig via SSH

Lokaal bouwen (als `docker compose` beschikbaar is):

```sh
cd /volume1/docker/scanbase
sudo docker compose up -d --build
sudo docker compose logs -f
```

Stoppen:

```sh
cd /volume1/docker/scanbase
sudo docker compose down
```
