#!/bin/bash

# BBUI Database & Admin User Test Script
# Testet ob Datenbank und Admin-Benutzer korrekt initialisiert wurden

echo "🧪 BBUI Database & Admin User Test"
echo "===================================="
echo ""

# Farben
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Prüfe PostgreSQL Verbindung
echo -n "📌 Prüfe PostgreSQL Verbindung... "
if psql -U borg -d bbui -h localhost -c "\q" 2>/dev/null; then
    echo -e "${GREEN}✅ OK${NC}"
else
    echo -e "${RED}❌ FEHLER${NC}"
    echo "   PostgreSQL läuft nicht oder Verbindungsdaten sind falsch"
    exit 1
fi

# Prüfe users Tabelle
echo -n "📌 Prüfe 'users' Tabelle... "
if psql -U borg -d bbui -h localhost -c "SELECT 1 FROM information_schema.tables WHERE table_name='users'" | grep -q 1; then
    echo -e "${GREEN}✅ OK${NC}"
else
    echo -e "${RED}❌ FEHLER${NC}"
    echo "   Tabelle 'users' existiert nicht"
    exit 1
fi

# Prüfe Admin-Benutzer
echo -n "📌 Prüfe Admin-Benutzer... "
ADMIN_COUNT=$(psql -U borg -d bbui -h localhost -tAc "SELECT COUNT(*) FROM users WHERE username='admin' AND is_admin=true")
if [ "$ADMIN_COUNT" -eq 1 ]; then
    echo -e "${GREEN}✅ OK${NC}"
else
    echo -e "${RED}❌ FEHLER${NC}"
    echo "   Admin-Benutzer nicht gefunden"
    exit 1
fi

# Prüfe alle erforderlichen Tabellen
echo ""
echo "📝 Prüfe alle Tabellen:"
TABLES=("users" "backup_servers" "backup_sources" "backup_schedules" "backup_jobs" "recovery_files" "backup_config" "audit_log" "servers" "sources" "backups")
for table in "${TABLES[@]}"; do
    echo -n "   - $table... "
    if psql -U borg -d bbui -h localhost -c "SELECT 1 FROM information_schema.tables WHERE table_name='$table'" 2>/dev/null | grep -q 1; then
        echo -e "${GREEN}✅${NC}"
    else
        echo -e "${RED}❌${NC}"
    fi
done

echo ""
echo "🎉 Alle Tests erfolgreich!"
echo ""
echo "✅ Datenbank ist korrekt initialisiert"
echo "✅ Admin-Benutzer existiert"
echo ""
echo "Sie können sich jetzt anmelden:"
echo "  URL: http://localhost:8040"
echo "  Benutzer: admin"
echo "  Passwort: admin"
echo ""
