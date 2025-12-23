# Changelog: SSH-Key Management Refactoring

## Version 2.0 - SSH-Key basiert (Neue Version)

### 🎉 Große Verbesserungen

#### ✅ curl API - Vereinfacht & Sicherer
**VORHER:**
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -d '{"hostname":"...","sshUsername":"...","sshPassword":"apt4auto"}'  # ❌ Passwort sichtbar!
```

**NACHHER:**
```bash
curl -X POST http://localhost:8040/api/addServerWithAuth \
  -d '{"name":"...","hostname":"...","sshUsername":"apt"}'  # ✅ Kein Passwort!
```

#### ✅ Admin-Bereich: SSH-Key Management
Neue Admin-APIs für zentrale Key-Verwaltung:
- `GET /api/admin/ssh-key-status` - Status prüfen
- `POST /api/admin/ssh-key-upload` - Key hochladen
- `GET /api/admin/ssh-key-download` - Key herunterladen
- `DELETE /api/admin/ssh-key` - Key löschen

#### ✅ Sicherheitsverbesserungen
- Keine Passwörter mehr in curl-Befehlen
- SSH-Key-basierte Authentifizierung (Standard)
- Keys mit `mode 0o600` (nur Owner lesbar)
- Zentrale Key-Verwaltung
- Audit-Logging für alle Admin-Operationen

#### ✅ Strukturverbesserungen
- Neue Verzeichnis: `/opt/bbui/patch-management/keys/`
- Default-Key: `/opt/bbui/patch-management/keys/default-key`
- Public-Key: `/opt/bbui/patch-management/keys/default-key.pub`

---

## Technische Details

### Neue Dateien

| Datei | Beschreibung |
|-------|------------|
| `SSH_KEY_MANAGEMENT.md` | Vollständige SSH-Key-Verwaltungs-Dokumentation |
| `ADMIN_SSH_KEY_SETUP.md` | Admin-Setup & Test-Anleitung |
| `CHANGELOG_SSH_KEY_REFACTOR.md` | Diese Datei |
| `keys/` (Verzeichnis) | SSH-Keys Speicherort |

### Geänderte Dateien

#### `index-borg.js`
- SSH-Key-Verzeichnis-Konfiguration hinzugefügt
- Admin-APIs für SSH-Key-Management hinzugefügt
  - `GET /api/admin/ssh-key-status`
  - `POST /api/admin/ssh-key-upload`
  - `DELETE /api/admin/ssh-key`
  - `GET /api/admin/ssh-key-download`
- `/api/addServerWithAuth` überarbeitet (jetzt SSH-Key basiert)
- Authentifizierungs-Middleware erweitert (neue public API)

#### Dokumentationen aktualisiert
- `ADD_SERVER_API.md` - Neue curl-API dokumentiert
- `API_SUMMARY.md` - Überblick aktualisiert

---

## Migration Guide: Alt → Neu

### Für Entwickler

**Alt (deprecated):**
```javascript
// SSH-Passwort wird übertragen
{"hostname":"...","sshUsername":"...","sshPassword":"..."}
```

**Neu (empfohlen):**
```javascript
// SSH-Key wird zentral verwaltet
{"name":"...","hostname":"...","sshUsername":"..."}
```

### Für Sys-Admins

**Alt:**
1. Passwörter in curl-Befehlen speichern ❌
2. SSH-Keys per Web-UI hochladen

**Neu:**
1. SSH-Key einmalig im Admin-Bereich hochladen ✅
2. curl-Befehle ohne Passwort verwenden ✅
3. Server beliebig hinzufügen (einfach!)

---

## Breaking Changes

⚠️ **curl API Parameter geändert:**
- `sshPassword` Parameter wurde ENTFERNT
- System benötigt jetzt Default SSH-Key (im Admin-Bereich)
- Alte Skripte müssen angepasst werden

**Alte curl-Befehle funktionieren nicht mehr!**

---

## Kompatibilität

✅ Web-UI: Kompatibel (Anpassung erforderlich)
✅ Datenbank: Kompatibel (keine Schema-Änderungen)
✅ Audit-Logging: Funktioniert
✅ Cron-Jobs: Nicht beeinflusst

---

## Testing

Alle neuen APIs getestet:
- ✅ SSH-Key Upload funktioniert
- ✅ curl API funktioniert ohne Passwort
- ✅ SSH-Verbindung mit Default-Key wird getestet
- ✅ Fehlermeldungen aussagekräftig
- ✅ Audit-Logging funktioniert

---

## Zukünftige Verbesserungen

📋 **Geplant:**
- [ ] Web-UI SSH-Key-Upload integrieren
- [ ] Multiple SSH-Keys pro Server unterstützen
- [ ] SSH-Key-Rotation automatisieren
- [ ] SSH-Agent Integration
- [ ] Hardware-Security-Key Support
- [ ] Key-Passphrases Support

---

## Kontakt & Support

Bei Fragen oder Problemen:
1. Siehe `SSH_KEY_MANAGEMENT.md`
2. Siehe `ADMIN_SSH_KEY_SETUP.md`
3. Überprüfen Sie `server.log`

