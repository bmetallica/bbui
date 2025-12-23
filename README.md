# 💾 BBUI – Borg Backup Management Interface

Ein vollständiges, webbasiertes Backup-Verwaltungssystem für Borg Backup mit Server-Management, automatischen Zeitplänen, SSHFS-Mounting und benutzerfreundlichem Recovery-Interface.

![BBUI Dashboard](https://via.placeholder.com/800x400?text=BBUI+Dashboard)

## �� Kernfunktionen

### 📊 Dashboard & Übersicht
- **Zentrale Verwaltungsplattform**: Gesamtübersicht aller Backup-Server und Quellen
- **Live-Statistiken**: Anzahl Server, Quellen, erfolgreiche Backups in Echtzeit
- **Speicherplatz-Monitoring**: Verfügbarer/Genutzter Speicherplatz mit Echtzeit-Visualisierung
- **Backup-Historie**: Letzte 10 Sicherungen mit Status-Anzeige

### 🖥️ Server-Management
- **Flexible Server-Konfiguration**: Unbegrenzte Anzahl von SSH-Servern
- **SSH-Key-Management**: 
  - Default SSH-Key für alle Server
  - Server-spezifische Custom SSH-Keys
  - Public- und Private-Key-Upload
- **Automatische Quellen-Verwaltung**: Konfiguriere Remote-Pfade für Backups
- **SSHFS-Mounting**: Automatisches Mounting und Unmounting während Backups
- **Backup-Repositories**: Automatische Erstellung und Verwaltung von Borg-Repositories

### ⏰ Automatisierung
- **Flexible Zeitplanung**: Stündlich, täglich, wöchentlich oder monatlich
- **Cron-Job-Management**: Automatische Verwaltung von Backup-Prozessen
- **Automatisches Cleanup**: Periodische Repository-Kompaktierung (Deduplication)
- **Fehlertoleranz**: Automatisches Unmounting bei Fehlern

### 💾 Backup-Funktionen
- **Borg Backup Integration**: Vollständige Unterstützung für Borg Backup
- **Kompression**: Automatische Compression (zstd, Level 10)
- **Inkrementelle Backups**: Effiziente Speichernutzung durch Deduplication
- **Archiv-Management**: Automatische Versionierung mit Zeitstempel
- **Progress-Tracking**: Echtzeit-Fortschrittsanzeige während Backups

### 🔍 Recovery & Wiederherstellung
- **Backup-Browsing**: Durchsuche und findel Files in Backups
- **Sichere Wiederherstellung**: Selektive Dateien oder komplette Archive
- **Dateibaum-Anzeige**: Hierarchische Sicht auf Backup-Inhalte
- **Zeitgesteuerte Recovery**: Wähle aus verschiedenen Backup-Versionen

### 🔐 Sicherheit & Authentifizierung
- **Benutzer-Management**: Sichere Login mit Passwort-Hashing (bcrypt)
- **Session-Management**: Automatisches Timeout nach 24 Stunden
- **Rollenbasierte Zugriffe (RBAC)**: Admin- und Standard-Benutzer
- **Audit-Logging**: Vollständige Nachverfolgung aller Aktionen
- **SSH-Key-Sicherheit**: Sichere Speicherung mit Dateiberechtigungen (0o600/0o700)

### ⚙️ Administration
- **Konfigurierbare Speicherorte**: Backup-Pfad kann im Admin-Panel geändert werden
- **NFS/Netzwerk-Support**: Unterstützung für Remote-Speicher
- **Systemd-Integration**: Als Service installierbar und autostart-enabled
- **Persistente Logs**: Systemd-Journal für Troubleshooting


---

## 🚀 Voraussetzungen (für manuelle Installation)

- **Debian/Ubuntu-Server** mit SSH-Zugriff (optional)
- **Node.js** 16+ mit npm
- **PostgreSQL** 12+ Datenbank
- **Borg Backup** installiert (`apt install borgbackup`)
- **SSHFS** für Remote-Backups (`apt install sshfs`)
- **Root-Zugriff** für SSHFS-Mounting und Verzeichnis-Verwaltung

---

## 📦 Manuelle Installation

### 1. Code herunterladen

```bash
cd /opt/
git clone https://github.com/bmetallica/bbui.git
cd bbui/bbui-borg
```

### 2. Node.js Dependencies installieren

```bash
npm install
```

---

## 🗄️ PostgreSQL vorbereiten

### 1. Datenbank und Benutzer anlegen

```bash
sudo -u postgres psql <<EOF
CREATE USER borg WITH PASSWORD 'borg';
CREATE DATABASE bbui OWNER borg;
GRANT ALL PRIVILEGES ON DATABASE bbui TO borg;
EOF
```

### 2. Tabellen initialisieren


Die Tabellen werden beim ersten Start automatisch erstellt.

---

## 🔧 Konfiguration

### 1. Datenbankverbindung anpassen (in index.js)

```javascript
const pool = new Pool({
    user: 'borg',
    host: 'localhost',
    database: 'bbui',
    password: 'borg',
    port: 5432
});
```

### 2. Port anpassen (optional)

```javascript
const port = 8040; // In index.js ändern
```

---

## 🚀 Anwendung starten

### Option 1: Mit Systemd Service (empfohlen - Root erforderlich)

```bash
# Service-Datei kopieren
sudo cp /opt/bbui/bbui-borg/bbui.service /etc/systemd/system/

# Systemd neu laden
sudo systemctl daemon-reload

# Service starten
sudo systemctl start bbui

# Beim Boot automatisch starten
sudo systemctl enable bbui

# Status prüfen
sudo systemctl status bbui

# Logs ansehen (Live)
sudo journalctl -u bbui -f
```

### Option 2: Direkt mit Node.js starten

```bash
cd /opt/bbui/bbui-borg
node index.js
```

### Option 3: Mit npm start

```bash
cd /opt/bbui/bbui-borg
npm start
```

---

## 🌐 Zugriff

Das Webinterface ist nach Installation erreichbar unter:

```
http://localhost:8040
```

(Port kann in `index.js` angepasst werden)

---

## 🔑 Login

Standard-Zugangsdaten:

| Feld | Wert |
|------|------|
| **Benutzername** | admin |
| **Passwort** | admin |

⚠️ **Wichtig**: Passwort nach dem ersten Login ändern!

---

## 🎯 Quick Start

### 1. Server hinzufügen

1. Im Webinterface anmelden (admin/admin)
2. Zum Tab "Server" gehen
3. "Neuen Server hinzufügen" klicken
4. SSH-Credentials eingeben
5. SSH-Key-Option wählen (Default oder Custom)
6. Speichern

### 2. Backup-Quelle erstellen

1. Auf einen Server klicken
2. "+ Quelle" Button drücken
3. Name und Remote-Pfad eingeben
4. Optional: Zeitplan festlegen
5. Speichern

### 3. Backup starten

1. Im Tab "Backups" die Quelle auswählen
2. "Backup jetzt starten" klicken
3. Fortschritt beobachten (Live-Updates)
4. Nach erfolgreicher Vollendung wird Archive in Borg-Repository gespeichert

### 4. Daten wiederherstellen

1. Im Tab "Recovery" die Quelle auswählen
2. Gewünschtes Backup-Archiv auswählen
3. Dateibaum durchsuchen
4. Gewünschte Dateien auswählen
5. "Wiederherstellen" klicken

---

## 🐛 Troubleshooting

### "Keine Berechtigung für /mnt/backup-sources"

```bash
sudo chmod 777 /mnt/backup-sources
```

### SSHFS-Mount schlägt fehl

```bash
# SSHFS installiert?
apt install sshfs

# SSH-Key vorhanden?
ls -la /opt/bbui/bbui-borg/keys/default-key

# SSH-Zugriff testbar?
ssh -i /opt/bbui/bbui-borg/keys/default-key user@host ls -la /remote/path
```

### Logs prüfen

```bash
# Systemd-Journal live
sudo journalctl -u bbui -f

# Letzte 50 Zeilen
sudo journalctl -u bbui -n 50

# Nur Fehler
sudo journalctl -u bbui -p err
```

---

## 📚 Dokumentation

Weitere Informationen:
- [BORG_BACKUP_README.md](./BORG_BACKUP_README.md) - Technische Architektur
- [Borg Backup Dokumentation](https://borgbackup.readthedocs.io/)
- [PostgreSQL Dokumentation](https://www.postgresql.org/docs/)

---

## 📝 Lizenz

MIT License

---

## 🎉 Viel Spaß mit diesem Projekt!

Autor: [bmetallica](https://github.com/bmetallica)

