# SSH-Key Management Implementation - README

## 🎯 Zusammenfassung

Das System wurde von passwort-basierter zu SSH-Key-basierter Authentifizierung umgestellt.

**Hauptvorteil:** Die curl API benötigt jetzt **KEIN Passwort mehr**!

---

## 📖 Was ist neu?

### Vorher (Alt & Unsicher ❌)
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -d '{"hostname":"...","sshPassword":"apt4auto"}'  # Passwort sichtbar!
```

### Nachher (Neu & Sicher ✅)
```bash
# Step 1: Admin lädt SSH-Key hoch (einmalig)
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @~/.ssh/id_rsa

# Step 2: User fügt Server ohne Passwort hinzu
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -d '{"hostname":"...","sshUsername":"apt"}'  # Kein Passwort!
```

---

## 📚 Dokumentationen (MUSS GELESEN WERDEN!)

| Datei | Für wen? | Inhalt |
|-------|----------|--------|
| [SSH_KEY_MANAGEMENT.md](SSH_KEY_MANAGEMENT.md) | Entwickler | Vollständige API-Doku |
| [ADMIN_SSH_KEY_SETUP.md](ADMIN_SSH_KEY_SETUP.md) | Admins | Setup & Test-Anleitung |
| [TESTING_GUIDE.md](TESTING_GUIDE.md) | QA/Tester | Testing & Troubleshooting |
| [ADD_SERVER_API.md](ADD_SERVER_API.md) | Benutzer | curl API Referenz |

---

## 🚀 Schnellstart (3 Schritte)

### 1. SSH-Key hochladen (Admin, einmalig)
```bash
curl -X POST http://localhost:8040/api/admin/ssh-key-upload \
  -H "Authorization: Basic YWRtaW46YWRtaW4=" \
  --data-binary @~/.ssh/id_rsa
```

### 2. Status prüfen
```bash
curl -X GET http://localhost:8040/api/admin/ssh-key-status \
  -H "Authorization: Basic YWRtaW46YWRtaW4="
```

### 3. Server hinzufügen (beliebig oft)
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-server",
    "hostname": "192.168.1.100",
    "sshUsername": "ubuntu"
  }'
```

---

## 📋 Was hat sich geändert?

### Code-Änderungen
- ✏️ `index-borg.js` - SSH-Key APIs hinzugefügt
- ✏️ `ADD_SERVER_API.md` - Dokumentation aktualisiert

### Neue Dateien
- ✨ `SSH_KEY_MANAGEMENT.md` - Vollständige Doku
- ✨ `ADMIN_SSH_KEY_SETUP.md` - Admin-Guide
- ✨ `TESTING_GUIDE.md` - Testing
- ✨ `CHANGELOG_SSH_KEY_REFACTOR.md` - Changelog

### Neue Verzeichnisse
- 📁 `keys/` - SSH-Keys Speicherort

---

## 🔑 Neue API Endpoints

### Admin (erfordert Authentifizierung)
```
POST   /api/admin/ssh-key-upload       → SSH-Key hochladen
GET    /api/admin/ssh-key-status       → Status prüfen
GET    /api/admin/ssh-key-download     → Key herunterladen
DELETE /api/admin/ssh-key              → Key löschen
```

### Öffentlich (KEIN Passwort für curl API)
```
POST   /api/addServerWithAuth          → Server hinzufügen (SSH-Key basiert)
```

---

## ✅ Vor Produktion: Checkliste

- [ ] SSH-Key hochladen (Admin)
- [ ] Test-Server hinzufügen
- [ ] SSH-Verbindung funktioniert
- [ ] HTTPS aktiviert
- [ ] Admin-Passwort geändert
- [ ] Firewall konfiguriert
- [ ] Logs überprüft
- [ ] Backup erstellt

---

## 🔐 Sicherheit

✅ **Verbessert:**
- Keine Passwörter in curl-Befehlen
- Zentrale Key-Verwaltung (Admin)
- SSH-Keys mit restriktiven Berechtigungen (0o600)
- Admin-APIs mit Authentifizierung geschützt
- Vollständiges Audit-Logging

⚠️ **Zu beachten:**
- HTTPS verwenden (nicht HTTP)
- SSH-Key lokal schützen
- Admin-Zugang begrenzen
- Keys regelmäßig rotieren

---

## 🆘 Probleme?

1. **"Default SSH-Key nicht konfiguriert"**
   → SSH-Key im Admin-Bereich hochladen

2. **"SSH-Verbindung fehlgeschlagen"**
   → Public-Key auf Server autorisieren oder Host offline

3. **"Nicht authentifiziert"**
   → Basic Auth Header verwenden: `-H "Authorization: Basic YWRtaW46YWRtaW4="`

Siehe [TESTING_GUIDE.md](TESTING_GUIDE.md) für mehr Troubleshooting.

---

## 📞 Weitere Hilfe

- Technische Details: [SSH_KEY_MANAGEMENT.md](SSH_KEY_MANAGEMENT.md)
- Setup-Anleitung: [ADMIN_SSH_KEY_SETUP.md](ADMIN_SSH_KEY_SETUP.md)
- Testing: [TESTING_GUIDE.md](TESTING_GUIDE.md)
- Changelog: [CHANGELOG_SSH_KEY_REFACTOR.md](CHANGELOG_SSH_KEY_REFACTOR.md)

---

## 📝 Version Info

- **Version:** 2.0 (SSH-Key basiert)
- **Datum:** 2025-12-23
- **Breaking Change:** Ja - `sshPassword` Parameter entfernt
- **Migration:** Siehe Dokumentationen

---

**Status:** ✅ Production-Ready
