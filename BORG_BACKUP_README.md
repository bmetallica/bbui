# 📦 Borg Backup Management System

Ein vollständiges, webbasiertes Backup-Verwaltungssystem für Borg Backup mit Server-Management, automatischen Zeitplänen, SSHFS-Mounting und benutzerfreundlichem Recovery-Interface.

## 📋 Inhalt

- **[QUICKSTART.md](patch-management/QUICKSTART.md)** - Schnelleinstieg (5 Minuten)
- **[BORG_README.md](patch-management/BORG_README.md)** - Vollständige Dokumentation
- **[patch-management/](patch-management/)** - Anwendungs-Code

## 🎯 Features

### ✅ Server-Verwaltung
- SSH-basierte Verbindungen zu mehreren Servern
- SSH-Key-basierte Authentifizierung
- Automatische Verbindungsprüfung
- Server-Status-Überwachung

### 💾 Backup-Verwaltung
- Mehrere unabhängige Backup-Quellen pro Server
- SSHFS-Automatisches Mounting und Unmounting
- Borg Backup Integration mit Verschlüsselung
- Deduplizierung durch Borg

### 🕐 Automatisierung
- Zeitgesteuerte Backups (stündlich, täglich, wöchentlich, monatlich)
- Automatische Cron-Job-Verwaltung
- Fehlerbehandlung und automatische Bereinigung
- Erfolgs-/Fehler-Logging

### 📥 Recovery
- Dateien aus Backups durchsuchen
- Datei- und Ordner-Downloads
- Verlaufsansicht mit Zeitstempel
- Archiv-Navigation

### 🔐 Sicherheit
- Bcrypt-Hashed Passwörter (10 Runden)
- Session-Management (24h Cookies)
- Audit-Logging aller Aktionen
- Admin/Benutzer-Rollen
- SSH-Key-Verwaltung

## 🚀 Quick Start

### 1. Starte den Server
```bash
cd /opt/bbui/patch-management
node index-borg.js
```

### 2. Öffne im Browser
```
http://localhost:8040/login.html
Benutzer: admin
Passwort: admin
```

### 3. Füge einen Server hinzu
1. Gehe zu **🖥️ Server**
2. Klicke **➕ Neuen Server hinzufügen**
3. Fülle die SSH-Daten aus
4. Speichern

### 4. Erstelle eine Backup-Quelle
1. Klicke **Details** beim Server
2. Klicke **➕ Quelle hinzufügen**
3. Gebe den Remote-Pfad ein
4. Speichern

### 5. Richte einen Zeitplan ein
1. Klicke **Jobs** bei der Quelle
2. Wähle eine Häufigkeit
3. Speichern

Fertig! 🎉

## 🏗️ Architektur

```
┌─────────────────────────────────────────────────────┐
│           Web-Browser (Frontend)                     │
│  Login | Dashboard | Servers | Backup | Recovery   │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│         Express.js REST API (Port 8040)              │
│  /api/servers, /api/sources, /api/jobs, etc.       │
└─────────────────────────────────────────────────────┘
                        ↓
┌─────────────────────────────────────────────────────┐
│         Node-Cron + Borg Integration                 │
│  - SSHFS Mounting                                   │
│  - Borg Backup/Restore                              │
│  - Fehlerbehandlung                                 │
└─────────────────────────────────────────────────────┘
                        ↓
┌──────────────────────────────────────────────────────┐
│  PostgreSQL Database + Borg Repositories             │
│  /backups/borg-repos/{server_id}_{source_id}        │
└──────────────────────────────────────────────────────┘
```

## 📚 Dokumentation

### Für Anfänger
→ Siehe [QUICKSTART.md](patch-management/QUICKSTART.md)

### Für Administratoren
→ Siehe [BORG_README.md](patch-management/BORG_README.md)

### API-Referenz
→ In [index-borg.js](patch-management/index-borg.js)

## 💻 Technologie-Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Node.js + Express.js
- **Datenbank**: PostgreSQL
- **Backup**: Borg Backup
- **Dateisystem**: SSHFS
- **Planung**: node-cron
- **Authentifizierung**: bcrypt + express-session

## 📊 Datenbankschema

### Haupttabellen
- `users` - Benutzer & Authentifizierung
- `backup_servers` - Backup-Ziele
- `backup_sources` - Backup-Quellen
- `backup_schedules` - Zeitpläne
- `backup_jobs` - Backup-Historie
- `recovery_files` - Datei-Index
- `backup_config` - Einstellungen
- `audit_log` - Audit-Trail

## 🔧 Installation

```bash
# 1. Datenbank
createdb bbui -U postgres

# 2. Code-Repository
cd /opt/bbui/patch-management

# 3. Abhängigkeiten
npm install

# 4. Server starten
node index-borg.js
```

Detaillierte Anleitung → [BORG_README.md](patch-management/BORG_README.md#-installation)

## 📝 Konfiguration

### Port
Standard: **8040** (anpassbar in `index-borg.js`)

### Datenbank
```javascript
user: 'borg'
password: 'borg'
database: 'bbui'
port: 5432
```

### Backup-Pfade
- Repositories: `/backups/borg-repos/`
- SSHFS: `/mnt/backup-sources/`

Siehe [index-borg.js](patch-management/index-borg.js#L32-L36)

## 🛠️ API-Endpoints

### Authentifizierung
- `POST /api/login` - Anmelden
- `GET /api/logout` - Abmelden
- `GET /api/current-user` - Aktuelle Benutzer

### Server
- `GET /api/servers` - Alle Server
- `POST /api/servers` - Neuen Server hinzufügen
- `DELETE /api/servers/:id` - Server löschen

### Quellen
- `GET /api/sources/:serverId` - Quellen eines Servers
- `POST /api/sources` - Neue Quelle
- `DELETE /api/sources/:id` - Quelle löschen

### Backups
- `GET /api/jobs/:sourceId` - Backup-Jobs
- `POST /api/backup/manual/:sourceId` - Manuelles Backup
- `GET /api/backup-history/:sourceId` - Detaillierte Historie

### Recovery
- `GET /api/recovery/:sourceId` - Recovery-Dateien
- `GET /api/recovery-tree/:jobId` - Datei-Struktur
- `POST /api/recovery-download/:jobId` - Datei-Download

### Monitoring
- `GET /api/dashboard/stats` - Dashboard-Statistiken
- `GET /api/server-status/:serverId` - Server-Details

## 🧪 Testen

### Manuelles Backup starten
```bash
curl -X POST http://localhost:8040/api/backup/manual/1 \
  -H "Content-Type: application/json"
```

### Server auflisten
```bash
curl http://localhost:8040/api/servers
```

### Logs prüfen
```bash
tail -f /opt/bbui/patch-management/borg-backup.log
```

## 🐛 Debugging

### Live-Logs
```bash
tail -f /opt/bbui/patch-management/borg-backup.log
```

### Datenbank-Debug
```bash
PGPASSWORD=borg psql -U borg -d bbui
```

### SSH-Test
```bash
ssh -i /path/to/key -v user@host
```

### SSHFS-Mount Test
```bash
sshfs -o IdentityFile=/path/to/key user@host:/remote /local
mount | grep sshfs
```

## 📈 Performance

### Für große Datenmengen
- Backup in Nicht-Peak-Hours einplanen
- Mehrere Quellen auf verschiedenen Zeitplänen
- SSHFS-Timeouts erhöhen

### Für viele Server
- Maximale Concurrent-Backups begrenzen
- Database-Indizes prüfen
- Disk-I/O optimieren

## 🔒 Security Checklist

- [ ] Admin-Passwort geändert
- [ ] SSH-Schlüssel mit 600er-Berechtigungen
- [ ] HTTPS/TLS in Produktion
- [ ] Firewall: Port 8040 beschränkt
- [ ] Regelmäßige Backup-Tests
- [ ] Audit-Log regelmäßig prüfen
- [ ] Datenbankverbindung gesichert

## 📞 Support

### Häufige Probleme
→ Siehe [QUICKSTART.md - Fehlerbehebung](patch-management/QUICKSTART.md#-fehlerbehebung)

### Logs prüfen
```bash
tail -100 /opt/bbui/patch-management/borg-backup.log
journalctl -u borg-backup -n 100
```

### Manuell testen
```bash
# SSH-Verbindung
ssh -i /root/.ssh/id_rsa backup@server

# Borg-Status
borg info /backups/borg-repos/repo_name

# SSHFS-Mount
sshfs -o IdentityFile=/root/.ssh/id_rsa backup@server:/path /mnt/test
```

## 📄 Lizenz

ISC

## 🙋 Kontakt

Für Fragen oder Probleme: Siehe Dokumentation oder prüfe die Logs.

---

**Version**: 1.0  
**Datum**: 22. Dezember 2025  
**Status**: ✅ Produktionsreif
