# Admin SSH-Key Management - Setup & Test Guide

## Schnellstart-Anleitung

### 1. SSH-Key hochladen

#### Option A: Mit Web-Browser (Admin-Panel)
Öffnen Sie: `http://localhost:8040/login.html`
1. Login mit `admin:admin`
2. Gehen Sie zum Admin-Panel
3. "SSH-Key verwalten" → "Key hochladen"
4. Wählen Sie Ihre `~/.ssh/id_rsa` (oder andere Private-Key-Datei)
5. "Hochladen" klicken

#### Option B: Mit curl (für Tests)
```bash
# Basic Auth: admin:admin → Base64: YWRtaW46YWRtaW4=
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @~/.ssh/id_rsa
```

### 2. SSH-Key Status prüfen

```bash
curl -X GET http://localhost:8040/api/admin/ssh-key-status \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

**Response (erfolgreich):**
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

### 3. Server mit curl hinzufügen (einfach!)

```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "prod-server-01",
    "hostname": "192.168.1.100",
    "sshUsername": "apt"
  }'
```

---

## Test-Szenario (komplettes Beispiel)

### Schritt 1: Test-Key generieren
```bash
ssh-keygen -t rsa -f ~/my-test-key -N "" -C "test@example.com"
```

### Schritt 2: Key hochladen
```bash
# Base64 encode: echo -n "admin:admin" | base64 → YWRtaW46YWRtaW4=
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @~/my-test-key
```

**Erwartete Response:**
```json
{
  "success": true,
  "message": "SSH-Key erfolgreich hochgeladen",
  "privateKeyPath": "/opt/bbui/patch-management/keys/default-key",
  "publicKeyPath": "/opt/bbui/patch-management/keys/default-key.pub"
}
```

### Schritt 3: Status prüfen
```bash
curl -X GET http://localhost:8040/api/admin/ssh-key-status \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

**Response sollte zeigen:**
```json
{
  "hasPrivateKey": true,
  "hasPublicKey": true,
  ...
}
```

### Schritt 4: Server hinzufügen (curl - ohne Passwort!)
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-server",
    "hostname": "example.com",
    "sshUsername": "ubuntu"
  }'
```

**Bei erfolgreichem SSH-Zugriff:**
```json
{
  "success": true,
  "id": 1,
  "message": "Server example.com erfolgreich hinzugefügt.",
  "server": {
    "id": 1,
    "name": "my-server",
    "hostname": "example.com",
    "ssh_user": "ubuntu",
    "ssh_port": 22,
    "ssh_key_path": "/opt/bbui/patch-management/keys/default-key"
  }
}
```

---

## Admin-API Referenz

### GET /api/admin/ssh-key-status
**Auth:** Admin-Login erforderlich

Gibt den Status des Default SSH-Keys zurück.

```bash
curl -X GET http://localhost:8040/api/admin/ssh-key-status \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

### POST /api/admin/ssh-key-upload
**Auth:** Admin-Login erforderlich

Lädt einen neuen Default SSH-Key hoch (ersetzt den alten).

```bash
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @~/.ssh/id_rsa
```

### GET /api/admin/ssh-key-download
**Auth:** Admin-Login erforderlich

Lädt den aktuellen Default SSH-Key herunter (nur Private-Key).

```bash
curl -X GET http://localhost:8040/api/admin/ssh-key-download \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  -o my-backup-key
chmod 600 my-backup-key
```

### DELETE /api/admin/ssh-key
**Auth:** Admin-Login erforderlich

Löscht den Default SSH-Key (PUBLIC UND PRIVATE).

```bash
curl -X DELETE http://localhost:8040/api/admin/ssh-key \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

---

## Troubleshooting

### Problem: "Default SSH-Key nicht konfiguriert"
**Ursache:** Kein Key in `/opt/bbui/patch-management/keys/default-key` vorhanden

**Lösung:**
```bash
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @~/.ssh/id_rsa
```

### Problem: "SSH-Verbindung fehlgeschlagen"
**Ursache:** Der SSH-Key kann sich nicht beim Remote-Server anmelden

**Lösung:**
1. Prüfen Sie ob der Public-Key auf dem Server im `~/.ssh/authorized_keys` ist
2. Testen Sie manuell:
   ```bash
   ssh -i /opt/bbui/patch-management/keys/default-key user@hostname "echo OK"
   ```
3. Kopieren Sie den Public-Key ggf. manuell:
   ```bash
   ssh-copy-id -i /opt/bbui/patch-management/keys/default-key.pub user@hostname
   ```

### Problem: "Nicht authentifiziert"
**Ursache:** Admin-Endpoints benötigen Login

**Lösung:** Verwenden Sie Basic Auth im Header:
```bash
-H "Authorization: Basic YWRtaW46YWRtaW4="
```

(Das ist: `echo -n "admin:admin" | base64`)

---

## Sicherheits-Checkliste

✅ SSH-Keys werden mit `mode 0o600` gespeichert (nur Owner lesbar)
✅ Passwörter nicht mehr in curl-Befehlen erforderlich
✅ Admin-APIs benötigen Authentifizierung
✅ SSH-Key-Passwort wird nicht lokal gespeichert
✅ Audit-Logging aller Admin-Operationen

⚠️ **Tipps für Produktion:**
- Verwenden Sie HTTPS (nicht HTTP)
- Schützen Sie `/opt/bbui/patch-management/keys/` mit Firewall
- Rotieren Sie SSH-Keys regelmäßig
- Verwenden Sie starke Admin-Passwörter
- Überwachen Sie Admin-Logs auf verdächtige Aktivitäten
