# SSH-Key Management API und Server-Erstellung

## Übersicht

Das System wurde überarbeitet um sicherer und konsistenter zu sein:
- **Admin-Bereich:** SSH-Key-Management (Default-Key hochladen/löschen)
- **Web-UI:** Server mit Default-Key oder Custom-Key erstellen
- **curl API:** Neue, vereinfachte API die nur noch Name, Hostname, Username benötigt (kein Passwort mehr!)

## 1. Admin-Bereich: SSH-Key Management

### Status des Default SSH-Keys abrufen
```bash
curl -X GET http://localhost:8040/api/admin/ssh-key-status \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)"
```

**Response:**
```json
{
  "hasPrivateKey": true,
  "hasPublicKey": true,
  "fileStats": {
    "created": "2025-12-23T09:00:00.000Z",
    "modified": "2025-12-23T09:00:00.000Z",
    "size": 1704
  },
  "keyPath": "/opt/bbui/patch-management/keys/default-key"
}
```

### Default SSH-Key hochladen
```bash
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  --data-binary @~/.ssh/id_rsa
```

**Response:**
```json
{
  "success": true,
  "message": "SSH-Key erfolgreich hochgeladen",
  "privateKeyPath": "/opt/bbui/patch-management/keys/default-key",
  "publicKeyPath": "/opt/bbui/patch-management/keys/default-key.pub"
}
```

### Default SSH-Key herunterladen
```bash
curl -X GET http://localhost:8040/api/admin/ssh-key-download \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  -o my-backup-key
chmod 600 my-backup-key
```

### Default SSH-Key löschen
```bash
curl -X DELETE http://localhost:8040/api/admin/ssh-key \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)"
```

**Response:**
```json
{
  "success": true,
  "message": "SSH-Key erfolgreich gelöscht"
}
```

---

## 2. curl API: Server mit Default SSH-Key hinzufügen

**Wichtig:** Diese API benötigt KEINEN Default SSH-Key in der Anfrage. Sie nutzt den im Admin-Bereich hochgeladenen Default-Key!

### Vereinfachter curl-Befehl

```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-server-01",
    "hostname": "192.168.1.100",
    "sshUsername": "apt"
  }'
```

**Parameter:**
| Parameter | Erforderlich | Beschreibung |
|-----------|-------------|-------------|
| `name` | Ja | Name des Servers |
| `hostname` | Ja | IP oder Hostname |
| `sshUsername` | Ja | SSH-Benutzername |
| `sshPort` | Nein | SSH-Port (Default: 22) |
| `description` | Nein | Beschreibung |

### Erfolgreiche Response (HTTP 200)

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

### Fehlerfälle

**Default SSH-Key nicht vorhanden (HTTP 400):**
```json
{
  "error": "Default SSH-Key nicht konfiguriert. Bitte laden Sie einen SSH-Key im Admin-Bereich hoch."
}
```

**SSH-Verbindung fehlgeschlagen (HTTP 500):**
```json
{
  "error": "Fehler beim Hinzufügen des Servers: SSH-Verbindung fehlgeschlagen: Permission denied (publickey)."
}
```

**Server existiert bereits (HTTP 409):**
```json
{
  "error": "Server mit diesem Hostname existiert bereits in der Datenbank."
}
```

---

## 3. Workflow: Komplettes Beispiel

### Schritt 1: Admin-Bereich - Default SSH-Key hochladen

```bash
# Auf der Admin-Seite oder per curl:
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic $(echo -n 'admin:admin' | base64)" \
  --data-binary @/home/user/.ssh/id_rsa
```

### Schritt 2: Beliebig viele Server hinzufügen (ohne Passwort!)

```bash
#!/bin/bash

API="http://localhost:8040/api/addServerWithAuth"

# Server 1
curl -X POST $API -H "Content-Type: application/json" \
  -d '{"name":"prod-web-01","hostname":"10.0.1.10","sshUsername":"apt"}'

# Server 2
curl -X POST $API -H "Content-Type: application/json" \
  -d '{"name":"prod-db-01","hostname":"10.0.2.20","sshUsername":"deploy"}'

# Server 3 mit Custom-Port
curl -X POST $API -H "Content-Type: application/json" \
  -d '{"name":"remote-backup","hostname":"backup.example.com","sshUsername":"backup","sshPort":2222}'
```

---

## 4. Web-UI Integration (zukünftig)

Im Web-UI beim Server erstellen:

1. **Option 1: Default SSH-Key verwenden**
   - Automatisch der hochgeladene Default-Key
   - Einfach und schnell

2. **Option 2: Neuen SSH-Key hochladen**
   - Per File-Upload
   - Wird server-spezifisch gespeichert

---

## 5. Sicherheitsverbesserungen

✅ **Vorher:** SSH-Passwort in curl-Befehlen (unsicher!)
```bash
curl ... -d '{"sshPassword":"apt4auto"}'  # ❌ Passwort sichtbar!
```

✅ **Nachher:** Nur SSH-Keys (sicher!)
```bash
curl ... -d '{"name":"...","hostname":"...","sshUsername":"apt"}'  # ✅ Kein Passwort!
```

**Weitere Sicherheitsfeatures:**
- SSH-Keys mit `mode 0o600` (nur Owner kann lesen)
- Default-Key zentral verwaltet (Single Point of Authority)
- Keine Passwörter mehr in curl-Befehlen
- Audit-Logging aller SSH-Key-Operationen

---

## 6. SSH-Keys Verzeichnis-Struktur

```
/opt/bbui/patch-management/
├── keys/
│   ├── default-key         (Private Key, mode 0o600)
│   └── default-key.pub     (Public Key, mode 0o644)
├── index-borg.js
└── ...
```

---

## 7. Troubleshooting

**Problem:** "Default SSH-Key nicht konfiguriert"
**Lösung:** SSH-Key im Admin-Bereich hochladen

**Problem:** "SSH-Verbindung fehlgeschlagen: Permission denied"
**Lösung:** 
- Überprüfen Sie ob der SSH-Key für den Benutzer autorisiert ist
- Oder kopieren Sie den öffentlichen Key auf den Remote-Server:
  ```bash
  ssh-copy-id -i /opt/bbui/patch-management/keys/default-key.pub user@hostname
  ```

**Problem:** "SSH-Key hat ungültiges Format"
**Lösung:** Stellen Sie sicher, dass Sie einen RSA-Key hochladen:
```bash
ssh-keygen -t rsa -f my-key -N ""
```

---

## 8. API Endpoints Übersicht

| Method | Endpoint | Beschreibung | Auth |
|--------|----------|-------------|------|
| GET | `/api/admin/ssh-key-status` | Status des Default-Keys | Admin |
| POST | `/api/admin/ssh-key-upload` | Default-Key hochladen | Admin |
| GET | `/api/admin/ssh-key-download` | Default-Key herunterladen | Admin |
| DELETE | `/api/admin/ssh-key` | Default-Key löschen | Admin |
| POST | `/api/addServerWithAuth` | Server mit Default-Key hinzufügen | ❌ Nein |

---

## 9. Migration von Alt zu Neu

Wenn Sie vorher die alte curl-API mit Passwort verwendet haben:

**Alt (nicht mehr empfohlen):**
```bash
curl ... -d '{"sshPassword":"apt4auto", ...}'
```

**Neu (empfohlen):**
1. SSH-Key hochladen: `/api/admin/ssh-key-upload`
2. curl ohne Passwort: `/api/addServerWithAuth`
