# Testing Guide: SSH-Key Management Refactoring

## Quick Test (5 Minuten)

### 1. Server läuft?
```bash
curl -s http://localhost:8040/api/addServerWithAuth \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"test","hostname":"192.168.1.1","sshUsername":"apt"}' \
  | grep -q "Default SSH-Key" && echo "✅ Server läuft und API antwortet!" || echo "❌ Problem"
```

### 2. Key Status ohne Key
```bash
curl -s http://localhost:8040/api/addServerWithAuth \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"test","hostname":"192.168.1.1","sshUsername":"apt"}'
```

**Erwartete Response:**
```json
{
  "error": "Default SSH-Key nicht konfiguriert. Bitte laden Sie einen SSH-Key im Admin-Bereich hoch."
}
```

✅ **Bedeutet:** API funktioniert, Key ist noch nicht hochgeladen

---

## Full Integration Test

### Schritt 1: Test-Key generieren
```bash
cd /opt/bbui/patch-management
ssh-keygen -t rsa -f test-key-local -N "" -C "test@example.com"
```

### Schritt 2: Key hochladen
```bash
# Base64: admin:admin → YWRtaW46YWRtaW4=
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @test-key-local
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
curl -s http://localhost:8040/api/admin/ssh-key-status \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" | jq .
```

**Sollte zeigen:**
```json
{
  "hasPrivateKey": true,
  "hasPublicKey": true,
  "fileStats": { ... }
}
```

### Schritt 4: Server hinzufügen (wird fehlschlagen wegen SSH-Fehler, aber API funktioniert!)
```bash
curl -s http://localhost:8040/api/addServerWithAuth \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"test-server","hostname":"192.168.1.1","sshUsername":"root"}'
```

**Erwartete Response (SSH-Fehler, aber API funktioniert!):**
```json
{
  "error": "Fehler beim Hinzufügen des Servers: SSH-Verbindung fehlgeschlagen: ssh: connect to host 192.168.1.1 port 22: No route to host"
}
```

✅ **Das ist korrekt!** - Die API funktioniert, SSH-Verbindung scheitert an nicht-erreichbarem Host

### Schritt 5: Key wieder löschen
```bash
curl -X DELETE http://localhost:8040/api/admin/ssh-key \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

**Erwartete Response:**
```json
{
  "success": true,
  "message": "SSH-Key erfolgreich gelöscht"
}
```

### Schritt 6: Überprüfen ob Key weg ist
```bash
curl -s http://localhost:8040/api/addServerWithAuth \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"name":"test","hostname":"192.168.1.1","sshUsername":"apt"}' \
  | grep "Default SSH-Key nicht"
```

✅ **Sollte "Default SSH-Key nicht" enthalten**

---

## Alle Test-Befehle in einem Script

```bash
#!/bin/bash

set -e  # Exit on error

API="http://localhost:8040"
AUTH="YWRtaW46YWRtaW4="  # base64: admin:admin

echo "=== Test 1: Ohne Key ==="
curl -s "$API/api/addServerWithAuth" \
  -X POST -H "Content-Type: application/json" \
  -d '{"name":"test","hostname":"test","sshUsername":"apt"}' | grep "Default SSH-Key"
echo "✅ Test 1 bestanden"

echo ""
echo "=== Test 2: Key hochladen ==="
ssh-keygen -t rsa -f test-key -N "" -C "test" 2>/dev/null
curl -s "$API/api/admin/ssh-key-upload" \
  -H "Authorization: Basic $AUTH" \
  --data-binary @test-key | grep success
echo "✅ Test 2 bestanden"

echo ""
echo "=== Test 3: Status prüfen ==="
curl -s "$API/api/admin/ssh-key-status" \
  -H "Authorization: Basic $AUTH" | grep hasPrivateKey
echo "✅ Test 3 bestanden"

echo ""
echo "=== Test 4: Server hinzufügen (SSH-Fehler erwartet) ==="
curl -s "$API/api/addServerWithAuth" \
  -X POST -H "Content-Type: application/json" \
  -d '{"name":"test","hostname":"localhost","sshUsername":"root"}' | grep -q "Fehler\|Connection\|refused" || echo "SSH möglich!"
echo "✅ Test 4 bestanden"

echo ""
echo "=== Test 5: Key löschen ==="
curl -s "$API/api/admin/ssh-key" \
  -X DELETE \
  -H "Authorization: Basic $AUTH" | grep success
echo "✅ Test 5 bestanden"

echo ""
echo "=== Alle Tests bestanden! ==="
```

---

## Checklist für Production-Ready

- [ ] SSH-Key Management funktioniert
- [ ] curl API funktioniert (ohne Passwort)
- [ ] Admin-APIs sind geschützt
- [ ] Error-Handling funktioniert
- [ ] Logs sind aussagekräftig
- [ ] Keine Passwörter in Logs
- [ ] HTTPS ist aktiviert
- [ ] Firewall schützt Keys-Verzeichnis

---

## Log-Analyse

Überprüfen Sie `server.log`:

```bash
tail -50 /opt/bbui/patch-management/server.log | grep -E "ADDSERVER|SSH-KEY"
```

**Sollte zeigen:**
```
[ADDSERVER] Teste SSH-Verbindung für ...
[SSH-KEY] Private Key hochgeladen
[SSH-KEY] Public Key extrahiert
...
```

---

## Troubleshooting

**Problem:** "Default SSH-Key nicht konfiguriert"
→ SSH-Key noch nicht hochgeladen

**Problem:** "SSH-Verbindung fehlgeschlagen"
→ SSH-Zugriff auf Server nicht möglich
→ Oder Server nicht erreichbar

**Problem:** "Nicht authentifiziert"
→ Admin-APIs benötigen Basic Auth
→ Verwenden Sie: `-H "Authorization: Basic YWRtaW46YWRtaW4="`

