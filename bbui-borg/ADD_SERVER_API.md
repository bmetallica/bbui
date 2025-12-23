# Curl API: Server mit Default SSH-Key hinzufügen

## ⚠️ WICHTIG: Diese API wurde neu gestaltet!

**Alte Version:** Benötigte SSH-Passwort (unsicher)
**Neue Version:** Nutzt Default SSH-Key (sicher und einfach)

## Schnellstart

### 1. Admin: SSH-Key hochladen
```bash
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  --data-binary @~/.ssh/id_rsa
```

### 2. Server hinzufügen (einfach!)
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-server",
    "hostname": "192.168.1.100",
    "sshUsername": "apt"
  }'
```

## Endpoint

**URL:** `POST http://localhost:8040/api/addServerWithAuth`

## Parameter

| Parameter | Typ | Erforderlich | Beschreibung |
|-----------|-----|--------------|-------------|
| `name` | String | Ja | Name/Beschreibung des Servers (z.B. `prod-server-01`) |
| `hostname` | String | Ja | IP-Adresse oder Hostname des Servers (z.B. `192.168.1.100`) |
| `sshUsername` | String | Ja | SSH-Benutzername (z.B. `apt`) |
| `sshPort` | Number | Nein | SSH-Port (Standard: 22) |
| `description` | String | Nein | Optionale Beschreibung |

## Antwort (Erfolg)

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
    "ssh_key_path": "/opt/bbui/patch-management/keys/default-key",
    "description": ""
  }
}
```

## Antwort (Fehler)

```json
{
  "error": "Fehlerbeschreibung"
}
```

## Beispiele

### 1. Einfles curl-Kommando
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-server-01",
    "hostname": "192.168.1.100",
    "sshUsername": "apt"
  }'
```

### 2. Mit optionalen Parametern
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "backup-server",
    "hostname": "backup.example.com",
    "sshUsername": "deploy",
    "sshPort": 2222,
    "description": "Produktions-Backup-Server"
  }' | jq .
```

### 3. Bash-Script für mehrere Server
```bash
#!/bin/bash

API_URL="http://localhost:8040/api/addServerWithAuth"
SERVERS=(
  '{"name": "server-01", "hostname": "192.168.1.100", "sshUsername": "apt"}'
  '{"name": "server-02", "hostname": "192.168.1.101", "sshUsername": "apt"}'
  '{"name": "server-03", "hostname": "192.168.1.102", "sshUsername": "root"}'
)

for server in "${SERVERS[@]}"; do
  echo "Füge Server hinzu: $server"
  curl -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d "$server"
  echo ""
done
```

## Was passiert beim Hinzufügen?

1. **SSH-Verbindung testen:** Der API testet die Verbindung mit dem Default SSH-Key
2. **SSH-Schlüssel kopieren:** Versucht, den öffentlichen SSH-Schlüssel zum Remote-Server zu kopieren
3. **Datenbank-Eintrag:** Der Server wird in der PostgreSQL-Datenbank registriert
4. **Audit-Log:** Die Aktion wird protokolliert

## Fehlerbehebung

### "SSH-Verbindung fehlgeschlagen"
- **Ursache:** SSH-Zugriff mit Default-Key nicht möglich
- **Lösung:** Überprüfen Sie ob der öffentliche Key auf dem Server autorisiert ist:
  ```bash
  ssh -i /opt/bbui/patch-management/keys/default-key apt@192.168.1.100 "echo OK"
  ```

### "Server mit diesem Hostname existiert bereits"
- **Ursache:** Ein Server mit diesem Hostname ist bereits registriert
- **Lösung:** Löschen Sie den alten Server oder verwenden Sie einen anderen Hostname

### "Default SSH-Key nicht konfiguriert"
- **Ursache:** Kein Default SSH-Key im Admin-Bereich hochgeladen
- **Lösung:** Laden Sie einen SSH-Key hoch:
  ```bash
  curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
    -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
    --data-binary @~/.ssh/id_rsa
  ```

## Sicherheitshinweise

✅ **Verbessert gegenüber älteren Versionen:**
- Keine SSH-Passwörter mehr in curl-Befehlen
- Zentrale SSH-Key-Verwaltung
- Keys werden mit 0o600 Berechtigungen gespeichert
- Empfehlung: HTTPS in der Produktion verwenden
- Firewall-Schutz für Admin-Endpoints

## Verwandte Admin-APIs

- `GET /api/admin/ssh-key-status` - Status des Default-Keys
- `POST /api/admin/ssh-key-upload` - SSH-Key hochladen
- `GET /api/admin/ssh-key-download` - SSH-Key herunterladen
- `DELETE /api/admin/ssh-key` - SSH-Key löschen

Siehe [SSH_KEY_MANAGEMENT.md](SSH_KEY_MANAGEMENT.md) für vollständige Details.

