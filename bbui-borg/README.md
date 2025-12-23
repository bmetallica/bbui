# BBUI - Borg Backup Management System

Eine moderne Weboberfläche zur Verwaltung von Borg Backup.

## Features

✅ **Backup-Server Management** - Verwalte Backup-Server und deren SSH-Verbindungen
✅ **Backup-Quellen Management** - Definiere Backup-Quellen (Verzeichnisse, Remote-Shares)
✅ **Scheduling** - Automatisierte Backup-Schedules mit Cron
✅ **Borg Repositories** - Verwalte Borg-Repositorys auf lokalen/Remote-Speichern
✅ **Recovery & Restore** - Wiederherstellen von Dateien und Verzeichnissen
✅ **SSH-Key Management** - Zentrale Verwaltung von SSH-Keys für Authentifizierung
✅ **Dashboard** - Übersicht über Backup-Status, Speicher, Schedules
✅ **Audit-Logging** - Alle Admin-Aktionen werden geloggt

## Architektur

```
/opt/bbui/bbui-borg/
├── index.js                          # Hauptanwendung (Node.js/Express)
├── public/
│   ├── backup.html                   # Web-UI (Borg Backup Management)
│   ├── login.html                    # Login-Seite
│   ├── styles.css                    # CSS-Styles
│   ├── images/                       # Statische Assets
├── keys/                             # SSH-Keys Verzeichnis
│   └── default-key                   # Default SSH-Private-Key
│   └── default-key.pub               # Default SSH-Public-Key
└── package.json                      # Node.js Dependencies
```

## Anforderungen

- **Node.js** 16.0+ 
- **PostgreSQL** 12.0+ (Datenbank)
- **Borg Backup** installiert
- **SSH** für Remote-Verbindungen

## Installation

### 1. Dependencies installieren

```bash
cd /opt/bbui/bbui-borg
npm install
```

### 2. PostgreSQL Datenbank setup

```bash
sudo su postgres
createdb bbui
createuser borg -P  # Passwort: borg
psql -d bbui -c "CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR UNIQUE, password_hash VARCHAR, is_admin BOOLEAN);"
psql -d bbui -c "CREATE TABLE backup_servers (id SERIAL PRIMARY KEY, name VARCHAR, hostname VARCHAR, ssh_port INT, ssh_user VARCHAR, status VARCHAR, created_at TIMESTAMP);"
# ... weitere Tabellen werden beim Start automatisch erstellt
```

### 3. Standard Admin-Benutzer

Der Admin-Benutzer wird beim Start automatisch erstellt:
- **Benutzername:** `admin`
- **Passwort:** `admin`

⚠️ **WICHTIG:** Ändern Sie das Passwort nach dem ersten Login!

### 4. SSH-Keys konfigurieren

Der Default SSH-Key wird im Admin-Panel hochgeladen:

1. Gehen Sie zu Admin → SSH-Key Management
2. Laden Sie Ihren Private SSH-Key hoch (`~/.ssh/id_rsa`)
3. Der Key wird automatisch für alle Server-Verbindungen verwendet


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


Die Anwendung läuft dann auf **http://localhost:8040**

## API-Dokumentation

### Authentifizierung

Alle API-Endpoints benötigen Authentifizierung:

#### 1. Session-basiert (Web-UI)
```bash
POST /api/login
{
  "username": "admin",
  "password": "admin"
}
```


### Wichtige Endpoints

| Methode | Endpoint | Beschreibung |
|---------|----------|-------------|
| GET | `/api/backup-servers` | Alle Backup-Server auflisten |
| POST | `/api/backup-servers` | Neuen Backup-Server hinzufügen |
| DELETE | `/api/servers/:id` | Backup-Server löschen |
| GET | `/api/backup-sources` | Backup-Quellen auflisten |
| POST | `/api/backup-sources` | Backup-Quelle hinzufügen |
| POST | `/api/schedules` | Backup-Schedule erstellen |
| GET | `/api/admin/ssh-key-status` | SSH-Key Status |
| POST | `/api/admin/ssh-key-upload` | SSH-Key hochladen |
| GET | `/api/admin/ssh-key-download` | SSH-Key herunterladen |
| DELETE | `/api/admin/ssh-key-delete` | SSH-Key löschen |


## Database Schema

Die Datenbank wird beim Start automatisch initialisiert mit folgenden Tabellen:

- **users** - Benutzer und Admin-Status
- **backup_servers** - Backup-Server
- **backup_sources** - Backup-Quellen
- **backup_schedules** - Cron-Schedules
- **backup_jobs** - Backup-Job-Historie
- **backup_config** - Konfigurationsparameter
- **audit_log** - Admin-Aktionen Logging

## Sicherheit

### SSH-Keys
- Private Keys werden mit Mode **0o600** gespeichert (nur Owner lesbar)
- Public Keys werden mit Mode **0o644** gespeichert
- Alle SSH-Keys-Operationen werden geloggt

### Admin-Zugriff
- Admin-Credentials: `admin:admin` (Standard)
- Basic Auth wird unterstützt für API-Zugriffe
- Session-basierte Auth für Web-UI
- Alle Admin-Aktionen werden in `audit_log` geloggt

## Bekannte Einschränkungen

1. Der Standard Admin-Benutzer hat hardcodierte Credentials
2. SSH-Key wird als Plaintext in der Datei gespeichert (sollte verschlüsselt werden)
3. Keine Benutzer-Rollen außer Admin/Normal


## Support & Dokumentation

Weitere Dokumentationen:
- [SSH-Key Management](SSH_KEY_MANAGEMENT.md) - SSH-Key API Dokumentation
- [Admin SSH-Key Setup](ADMIN_SSH_KEY_SETUP.md) - Setup-Guide für Administratoren
- [API Summary](API_SUMMARY.md) - Komplette API-Übersicht
- [Testing Guide](TESTING_GUIDE.md) - Testprozeduren



