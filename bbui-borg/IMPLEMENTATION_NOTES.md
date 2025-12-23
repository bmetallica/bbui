# Implementierungsnotizen: addServerWithAuth API

## Status: ✅ Implementiert und fertig

### Änderungen durchgeführt:

1. **Neue API hinzugefügt in `index-borg.js`** (Zeile ~225)
   - Endpoint: `POST /api/addServerWithAuth`
   - Port: **8040** (nicht 3030!)
   - Nicht passwortgeschützt
   - Funktioniert mit der Borg-Backup-Anwendung

2. **Dateimodifikationen:**
   - ✅ `patch-management/index-borg.js` - API hinzugefügt
   - ✅ `patch-management/index.js` - Duplikat entfernt (wird nicht verwendet)

3. **Neue Dokumentationsdateien:**
   - ✅ `ADD_SERVER_API.md` - Vollständige Dokumentation
   - ✅ `API_SUMMARY.md` - Kurzübersicht
   - ✅ `test_add_server.sh` - Test-Script
   - ✅ `quick_example.sh` - Beispiele

### Wichtige Details:

**Port:** 8040 (nicht 3030)
- Die Hauptanwendung läuft auf Port 8040
- Datei: `index-borg.js` (package.json zeigt dies als "main")

**Datenbankschema:** 
- Verwendet die bestehende Tabelle `backup_servers`
- Speichert SSH-Schlüssel lokal in `/tmp/borg_key_<timestamp>`
- Erstellt Audit-Logs

**SSH-Funktionalität:**
1. Testet Verbindung mit Passwort
2. Generiert neues RSA-Schlüsselpaar
3. Kopiert öffentlichen Schlüssel zum Server (optional, Fehler nicht kritisch)
4. Registriert Server in DB mit Schlüsselpfad

### API-Parameter:

```json
{
  "name": "prod-server-01",        // Erforderlich
  "hostname": "192.168.1.100",     // Erforderlich
  "sshUsername": "apt",            // Erforderlich
  "sshPassword": "apt4auto",       // Erforderlich
  "sshPort": 22,                   // Optional (Default: 22)
  "description": ""                // Optional
}
```

### Beispiel-Aufruf:

```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-server",
    "hostname": "192.168.1.100",
    "sshUsername": "apt",
    "sshPassword": "apt4auto"
  }'
```

### Test-Scripts:

```bash
# Interaktives Test-Script
./test_add_server.sh

# Mit Parametern
./test_add_server.sh prod-01 192.168.1.100 apt apt4auto

# Direktes curl
./quick_example.sh
```

### Sicherheit:

⚠️ **Achtung:**
- API ist NICHT passwortgeschützt
- SSH-Passwörter sind nur für die API-Anfrage erforderlich
- Nach erfolgreichem Hinzufügen werden SSH-Schlüssel verwendet (passwortlos)
- Verwenden Sie Firewall/VPN zum Schutz des Endpoints in Produktion
- HTTPS wird empfohlen für sichere Datenübertragung

### Integration mit bestehendem System:

Die API passt sich perfekt in die bestehende Borg-Anwendung ein:
- ✅ Verwendet gleiche Datenbank (`bbui`)
- ✅ Kompatibel mit existierenden Endpoints
- ✅ Audit-Logging funktioniert
- ✅ Keine Änderungen an anderen Funktionen notwendig

### Fehlerbehandlung:

- HTTP 400: Parameter fehlen
- HTTP 409: Server existiert bereits
- HTTP 500: SSH-Verbindung fehlgeschlagen oder DB-Fehler

