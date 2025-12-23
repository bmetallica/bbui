# Neue API: Server mit SSH-Authentifizierung hinzufügen

## Was wurde implementiert?

Ein neuer, **nicht passwortgeschützter** API-Endpoint wurde hinzugefügt, der es ermöglicht, Server mit SSH-Anmeldedaten über curl hinzuzufügen.

## Endpoint Details

**POST** `/api/addServerWithAuth`

### Parameter (JSON):
```json
{
  "name": "prod-server-01",        // Erforderlich: Name des Servers
  "hostname": "192.168.1.100",      // Erforderlich: Server-IP oder Hostname
  "sshUsername": "apt",             // Erforderlich: SSH-Benutzername
  "sshPassword": "apt4auto",        // Erforderlich: SSH-Passwort
  "sshPort": 22,                    // Optional: SSH-Port (Default: 22)
  "description": "Beschreibung"     // Optional: Server-Beschreibung
}
```

## Verwendungsbeispiele

### Einfacher curl-Befehl:
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-server-01",
    "hostname": "192.168.1.100",
    "sshUsername": "apt",
    "sshPassword": "apt4auto"
  }'
```

### Mit jq (für schönere Ausgabe):
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "backup-server",
    "hostname": "192.168.1.100",
    "sshUsername": "apt",
    "sshPassword": "apt4auto"
  }' | jq .
```

### Mehrere Server auf einmal:
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{"name":"server-01","hostname":"192.168.1.100","sshUsername":"apt","sshPassword":"apt4auto"}' && \
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{"name":"server-02","hostname":"192.168.1.101","sshUsername":"apt","sshPassword":"apt4auto"}'
```

## Was passiert beim Aufruf?

1. ✅ SSH-Verbindung wird getestet
2. ✅ SSH-Schlüsselpaar wird generiert
3. ✅ SSH-Schlüssel werden zum Remote-Server kopiert (für zukünftige passwortlose Verbindungen)
4. ✅ Server wird in der Datenbank registriert
5. ✅ Audit-Log-Eintrag wird erstellt

## Neue Dateien

| Datei | Beschreibung |
|-------|------------|
| [ADD_SERVER_API.md](ADD_SERVER_API.md) | Ausführliche API-Dokumentation mit allen Details und Fehlerbehebung |
| [test_add_server.sh](test_add_server.sh) | Interaktives Test-Script mit farbiger Ausgabe |
| [quick_example.sh](quick_example.sh) | Schnelle Beispiele zum Testen |

## Teste die API

### Option 1: Test-Script verwenden (interaktiv)
```bash
cd /opt/bbui/patch-management
./test_add_server.sh prod-server-01 192.168.1.100 apt apt4auto
```

### Option 2: Interaktiv
```bash
./test_add_server.sh
# Dann Werte eingeben, wenn dazu aufgefordert
```

### Option 3: Direktes curl
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-server-01",
    "hostname": "192.168.1.100",
    "sshUsername": "apt",
    "sshPassword": "apt4auto"
  }'
```

## Wichtige Sicherheitshinweise

⚠️ **Passwörter werden übertragen** - verwenden Sie HTTPS in Produktion!
- Verwenden Sie Firewall-Regeln oder VPN zum Schutz des Endpoints
- Ändern Sie Default-Passwörter nach dem ersten Start
- Die SSH-Schlüsselkopie ermöglicht später passwortlose Verbindungen (besser!)

## Rückgabe-Format

### Erfolg (HTTP 200):
```json
{
  "success": true,
  "id": 5,
  "message": "Server 192.168.1.100 erfolgreich hinzugefügt.",
  "server": {
    "id": 5,
    "name": "prod-server-01",
    "hostname": "192.168.1.100",
    "ssh_user": "apt",
    "ssh_port": 22,
    "ssh_key_path": "/tmp/borg_key_1703335200000"
  }
}
```

### Fehler - Parameter fehlen (HTTP 400):
```json
{
  "error": "Erforderliche Parameter fehlen: name, hostname, sshUsername, sshPassword"
}
```

### Fehler - Server existiert (HTTP 409):
```json
{
  "error": "Server mit diesem Hostname existiert bereits in der Datenbank."
}
```

### Fehler - SSH-Verbindung fehlgeschlagen (HTTP 500):
```json
{
  "error": "Fehler beim Hinzufügen des Servers: SSH-Verbindung fehlgeschlagen"
}
```

## Integration mit bestehenden APIs

Die neue API arbeitet nahtlos mit den existierenden Endpoints zusammen:

- Nach dem Hinzufügen können Sie Server-Backup-Quellen konfigurieren
- `/api/servers` zeigt alle registrierten Server an
- `/api/sources/:serverId` zeigt Backup-Quellen pro Server
- `/api/schedules` konfiguriert Backup-Zeitpläne

## Logs und Debugging

Alle Aktionen werden in der Server-Konsole geloggt:
```
[ADDSERVER] Teste SSH-Verbindung für apt@192.168.1.100...
[ADDSERVER] SSH-Verbindung erfolgreich für 192.168.1.100
[ADDSERVER] Generiere SSH-Schlüsselpaar...
[ADDSERVER] Kopiere SSH-Schlüssel zu 192.168.1.100...
[ADDSERVER] SSH-Schlüssel erfolgreich kopiert für 192.168.1.100
[ADDSERVER] Server 192.168.1.100 erfolgreich mit ID 5 hinzugefügt.
```

Zum Debugging SSH-Verbindungen manuell testen:
```bash
sshpass -p "apt4auto" ssh -o StrictHostKeyChecking=accept-new apt@192.168.1.100 "echo OK"
```

## Weitere Dokumentation

Siehe [ADD_SERVER_API.md](ADD_SERVER_API.md) für vollständige Details, erweiterte Beispiele und Fehlerbehebung.
