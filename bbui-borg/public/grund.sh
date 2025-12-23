#!/bin/bash

# Stellen Sie sicher, dass das Skript als root ausgeführt wird
if [[ $EUID -ne 0 ]]; then
   echo "Dieses Skript muss als root oder mit sudo ausgeführt werden."
   exit 1
fi

USER_NAME="apt"
USER_PASS="apt4auto"
SUDO_CONFIG_FILE="/etc/sudoers.d/90-${USER_NAME}-nopasswd"
ENV_FILE="/etc/environment"

# --- USER SETUP ---

echo "--- 1. Benutzer-Setup für '$USER_NAME' ---"

# 1. Benutzer anlegen
echo "👉 Erstelle den Benutzer '$USER_NAME'..."
useradd -m -s /bin/bash "$USER_NAME"

if [ $? -ne 0 ]; then
    echo "❌ Fehler beim Erstellen des Benutzers '$USER_NAME'. Beende Skript."
    exit 1
fi

# 2. Passwort festlegen
echo "🔒 Setze das Passwort für Benutzer '$USER_NAME'..."
echo "$USER_NAME:$USER_PASS" | chpasswd

# 3. sudo-Rechte ohne Passworteingabe hinzufügen
echo "🛡️ Konfiguriere 'sudo'-Rechte (NOPASSWD) für Benutzer '$USER_NAME'..."
echo "$USER_NAME ALL=(ALL) NOPASSWD: ALL" > "$SUDO_CONFIG_FILE"
chmod 0440 "$SUDO_CONFIG_FILE"

echo "✅ Benutzer '$USER_NAME' erfolgreich eingerichtet."

echo "---"

# --- PROXY SETUP ---

echo "--- 2. Proxy-Einstellungen in '$ENV_FILE' schreiben ---"

PROXY_SETTINGS=$(cat <<EOF
# Proxy Einstellungen
export http_proxy="http://proxy.rlp:8080"
export https_proxy="http://proxy.rlp:8080"
export ftp_proxy="http://proxy.rlp:8080"
export HTTP_PROXY="http://proxy.rlp:8080"
export HTTPS_PROXY="http://proxy.rlp:8080"
export FTP_PROXY="http://proxy.rlp:8080"
export no_proxy="192.168.122.1,localhost,127.0.0.1,::1"
export NO_PROXY="192.168.122.1,localhost,127.0.0.1,::1"
EOF
)

# Überprüfen, ob die Datei existiert (sollte auf Debian immer der Fall sein)
if [ ! -f "$ENV_FILE" ]; then
    echo "⚠️ Die Datei $ENV_FILE wurde nicht gefunden. Erstelle sie."
    touch "$ENV_FILE"
fi

# Füge die neuen Proxy-Einstellungen am Ende der Datei hinzu
echo "$PROXY_SETTINGS" >> "$ENV_FILE"

if [ $? -eq 0 ]; then
    echo "✅ Proxy-Einstellungen erfolgreich in $ENV_FILE geschrieben."
    echo "   (Ein Neustart oder Neuanmeldung ist erforderlich, damit diese global wirksam werden.)"
else
    echo "❌ Fehler beim Schreiben der Proxy-Einstellungen in $ENV_FILE."
fi

echo "---"
echo "🎉 Skript abgeschlossen."
