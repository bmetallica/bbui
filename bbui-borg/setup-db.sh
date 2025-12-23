#!/bin/bash

# BBUI Datenbank-Setup Script
# Erstellt PostgreSQL Benutzer und Datenbank

set -e

echo "🗄️  BBUI Datenbank-Setup"
echo "========================"

# Prüfe ob PostgreSQL läuft
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL nicht installiert. Bitte installieren Sie PostgreSQL:"
    echo "   sudo apt install postgresql postgresql-contrib"
    exit 1
fi

echo ""
echo "📝 Erstelle PostgreSQL Benutzer 'borg'..."

# Erstelle borg Benutzer (ignoriere Fehler falls existiert)
sudo -u postgres psql -c "CREATE USER borg WITH PASSWORD 'borg';" 2>/dev/null || echo "   ℹ️  Benutzer 'borg' existiert bereits"

echo "📝 Erstelle Datenbank 'bbui'..."

# Erstelle bbui Datenbank (ignoriere Fehler falls existiert)
sudo -u postgres psql -c "CREATE DATABASE bbui OWNER borg;" 2>/dev/null || echo "   ℹ️  Datenbank 'bbui' existiert bereits"

echo ""
echo "✅ PostgreSQL Datenbank-Setup abgeschlossen!"
echo ""
echo "Die Tabellen werden automatisch beim Start der BBUI-Anwendung erstellt."
echo "Starten Sie die Anwendung mit:"
echo "  cd /opt/bbui/bbui-borg"
echo "  sudo node index.js"
echo ""
echo "Login-Credentials:"
echo "  Benutzer: admin"
echo "  Passwort: admin"
echo ""
