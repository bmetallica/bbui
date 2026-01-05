// Borg Backup Management System - Backend
const express = require('express');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const cron = require('node-cron');
const { exec, spawn } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

const app = express();
const port = 8040;

// ===== KONFIGURATION =====
const ENABLE_LOGIN = true;
const DEFAULT_USERNAME = 'guest';
const saltRounds = 10;

// SSH-Key Konfiguration
const SSH_KEYS_DIR = path.join(__dirname, 'keys');
const DEFAULT_SSH_KEY_PATH = path.join(SSH_KEYS_DIR, 'default-key');
const DEFAULT_SSH_KEY_PUB_PATH = path.join(SSH_KEYS_DIR, 'default-key.pub');

// PostgreSQL-Verbindung
const pool = new Pool({
    user: 'borg',
    host: 'localhost',
    database: 'bbui',
    password: 'borg',
    port: 5432
});

// Borg Backup Konfiguration
let BACKUP_BASE_PATH = '/backups/borg-repos'; // Standard, wird aus DB überschrieben
const SSHFS_MOUNT_BASE = '/mnt/backup-sources';
const cronJobs = {}; // Speichert aktive Cron-Jobs

/**
 * Lädt Konfiguration aus der Datenbank
 */
async function loadConfiguration() {
    try {
        const result = await pool.query('SELECT key, value FROM backup_config');
        for (const row of result.rows) {
            if (row.key === 'backup_base_path') {
                BACKUP_BASE_PATH = row.value;
                console.log(`[CONFIG] Backup-Pfad aus DB geladen: ${BACKUP_BASE_PATH}`);
            }
        }
    } catch (error) {
        console.error('[CONFIG] Fehler beim Laden der Konfiguration:', error);
    }
}

// Stelle sicher, dass SSH-Keys-Verzeichnis existiert
if (!fs.existsSync(SSH_KEYS_DIR)) {
    fs.mkdirSync(SSH_KEYS_DIR, { recursive: true, mode: 0o700 });
}

// ===== MIDDLEWARE SETUP =====
app.use(session({
    secret: 'borg-backup-secret-key-2025',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static('public'));

// Root-Endpunkt: Redirecte zu backup.html
app.get('/', (req, res) => {
    res.redirect('/backup.html');
});

// ===== AUTHENTIFIZIERUNG =====

/**
 * Initialisiert die Datenbankstruktur und Admin-Benutzer
 */
async function initializeDatabase() {
    try {
        // Erstelle users Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_admin BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "users" existiert oder wurde erstellt');

        // Erstelle backup_servers Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS backup_servers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) UNIQUE NOT NULL,
                hostname VARCHAR(255) NOT NULL,
                ssh_port INTEGER DEFAULT 22,
                ssh_user VARCHAR(50) NOT NULL,
                ssh_key_path VARCHAR(255) NOT NULL,
                description TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_check TIMESTAMP,
                status VARCHAR(20) DEFAULT 'unknown'
            )
        `);
        console.log('[DB] Tabelle "backup_servers" existiert oder wurde erstellt');

        // Erstelle servers Tabelle (Legacy-Kompatibilität)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS servers (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                host VARCHAR(255) NOT NULL,
                port INTEGER DEFAULT 22,
                username VARCHAR(100) NOT NULL,
                ssh_key_path VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "servers" existiert oder wurde erstellt');

        // Erstelle backup_sources Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS backup_sources (
                id SERIAL PRIMARY KEY,
                server_id INTEGER NOT NULL REFERENCES backup_servers(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                remote_path VARCHAR(255) NOT NULL,
                description TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(server_id, name)
            )
        `);
        console.log('[DB] Tabelle "backup_sources" existiert oder wurde erstellt');

        // Erstelle sources Tabelle (Legacy-Kompatibilität)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS sources (
                id SERIAL PRIMARY KEY,
                server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
                remote_path VARCHAR(255) NOT NULL,
                backup_schedule VARCHAR(50) DEFAULT 'daily',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "sources" existiert oder wurde erstellt');

        // Erstelle backups Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS backups (
                id SERIAL PRIMARY KEY,
                server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE,
                source_id INTEGER REFERENCES sources(id) ON DELETE CASCADE,
                status VARCHAR(50),
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                size_bytes BIGINT,
                files_count INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "backups" existiert oder wurde erstellt');

        // Erstelle backup_config Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS backup_config (
                id SERIAL PRIMARY KEY,
                key VARCHAR(100) UNIQUE NOT NULL,
                value TEXT,
                description TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "backup_config" existiert oder wurde erstellt');

        // Erstelle backup_schedules Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS backup_schedules (
                id SERIAL PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES backup_sources(id) ON DELETE CASCADE,
                frequency VARCHAR(20) NOT NULL,
                cron_expression VARCHAR(100),
                enabled BOOLEAN DEFAULT TRUE,
                last_run TIMESTAMP,
                last_status VARCHAR(20) DEFAULT 'pending',
                last_error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "backup_schedules" existiert oder wurde erstellt');

        // Erstelle audit_log Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                action VARCHAR(100),
                resource_type VARCHAR(50),
                resource_id INTEGER,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "audit_log" existiert oder wurde erstellt');
        
        // Erstelle Indizes für audit_log
        await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at)');

        // Erstelle backup_jobs Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS backup_jobs (
                id SERIAL PRIMARY KEY,
                source_id INTEGER NOT NULL REFERENCES backup_sources(id) ON DELETE CASCADE,
                schedule_id INTEGER REFERENCES backup_schedules(id) ON DELETE SET NULL,
                job_date TIMESTAMP NOT NULL,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status VARCHAR(20) NOT NULL,
                error_message TEXT,
                bytes_backed_up BIGINT,
                repository_size BIGINT,
                archive_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "backup_jobs" existiert oder wurde erstellt');
        
        // Erstelle Indizes für backup_jobs
        await pool.query('CREATE INDEX IF NOT EXISTS idx_backup_jobs_source_id ON backup_jobs(source_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_backup_jobs_job_date ON backup_jobs(job_date)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_backup_jobs_status ON backup_jobs(status)');

        // Erstelle recovery_files Tabelle
        await pool.query(`
            CREATE TABLE IF NOT EXISTS recovery_files (
                id SERIAL PRIMARY KEY,
                backup_job_id INTEGER NOT NULL REFERENCES backup_jobs(id) ON DELETE CASCADE,
                file_path VARCHAR(1024) NOT NULL,
                file_type VARCHAR(20) NOT NULL,
                file_size BIGINT,
                modified_time TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log('[DB] Tabelle "recovery_files" existiert oder wurde erstellt');
        
        // Erstelle Indizes für recovery_files
        await pool.query('CREATE INDEX IF NOT EXISTS idx_recovery_files_backup_job_id ON recovery_files(backup_job_id)');
        await pool.query('CREATE INDEX IF NOT EXISTS idx_recovery_files_file_path ON recovery_files(file_path)');

        // Erstelle Admin-Benutzer, falls nicht vorhanden
        const checkUser = await pool.query('SELECT * FROM users WHERE username = $1', ['admin']);
        if (checkUser.rows.length === 0) {
            const passwordHash = await bcrypt.hash('admin', saltRounds);
            await pool.query(
                'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, TRUE)',
                ['admin', passwordHash]
            );
            console.log('[DB] ✅ Admin-Benutzer erstellt (username: admin, password: admin)');
        } else {
            console.log('[DB] Admin-Benutzer existiert bereits');
        }
    } catch (error) {
        console.error('[DB] Fehler beim Initialisieren der Datenbank:', error);
        throw error;
    }
}

/**
 * Middleware: Authentifizierung prüfen
 */
function requireLogin(req, res, next) {
    if (!ENABLE_LOGIN) {
        if (!req.session.userId) {
            req.session.userId = -1;
            req.session.username = DEFAULT_USERNAME;
            req.session.isAdmin = false;
        }
        return next();
    }

    // Öffentliche Pfade (keine Authentifizierung erforderlich)
    const publicPaths = ['/api/login', '/api/addServerWithAuth', '/login.html', '/backup.html', '/', '/index.html'];
    const publicExtensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'];
    
    // Öffentliche Pfade zulassen
    if (publicPaths.includes(req.path)) {
        return next();
    }
    
    // Statische Assets zulassen
    if (publicExtensions.some(ext => req.path.endsWith(ext))) {
        return next();
    }
    
    // API-Bootstrap Endpoints zulassen
    if (req.path.startsWith('/api/bootstrap/')) {
        return next();
    }
    
    // Admin-APIs mit Basic Auth erlauben
    if (req.path.startsWith('/api/admin/')) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Basic ')) {
            const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
            const [username, password] = credentials.split(':');
            
            // Überprüfe gegen Default-Admin-Credentials
            if (username === 'admin' && password === 'admin') {
                return next();
            }
        }
    }

    // Wenn Benutzer authentifiziert ist, weitermachen
    if (req.session && req.session.userId) {
        return next();
    }

    // Wenn API-Endpoint, JSON-Fehler zurückgeben
    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Nicht authentifiziert' });
    }

    // Sonst zur Login-Seite umleiten
    res.redirect('/login.html');
}

/**
 * Middleware: Admin-Prüfung
 */
function requireAdmin(req, res, next) {
    // Überprüfe Session-basierte Admin
    if (req.session && req.session.isAdmin) {
        return next();
    }
    
    // Überprüfe Basic Auth (für curl/API-Zugriffe)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
        const credentials = Buffer.from(authHeader.slice(6), 'base64').toString();
        const [username, password] = credentials.split(':');
        
        // Überprüfe gegen Default-Admin-Credentials
        if (username === 'admin' && password === 'admin') {
            return next();
        }
    }
    
    res.status(403).json({ error: 'Admin-Zugriff erforderlich' });
}

app.use(requireLogin);

// ===== AUTHENTIFIZIERUNGS-ENDPUNKTE =====

/**
 * POST /api/login - Benutzer anmelden
 */
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) {
            return res.status(401).json({ success: false, message: 'Benutzer nicht gefunden' });
        }

        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: 'Falsches Passwort' });
        }

        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.isAdmin = user.is_admin;

        res.json({ success: true, username: user.username, isAdmin: user.is_admin });
    } catch (error) {
        console.error('[LOGIN] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Anmelden' });
    }
});

/**
 * GET /api/logout - Benutzer abmelden
 */
app.get('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        res.json({ success: true });
    });
});

/**
 * GET /api/current-user - Aktuelle Benutzerinformationen
 */
app.get('/api/current-user', (req, res) => {
    if (req.session.userId) {
        res.json({
            userId: req.session.userId,
            username: req.session.username,
            isAdmin: req.session.isAdmin
        });
    } else {
        res.status(401).json({ error: 'Nicht authentifiziert' });
    }
});

/**
 * POST /api/change-password - Passwort ändern
 */
app.post('/api/change-password', async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    // Validiere Eingaben
    if (!currentPassword || !newPassword || !confirmPassword) {
        return res.status(400).json({ error: 'Alle Felder sind erforderlich' });
    }

    if (newPassword !== confirmPassword) {
        return res.status(400).json({ error: 'Neue Passwörter stimmen nicht überein' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Passwort muss mindestens 6 Zeichen lang sein' });
    }

    // Benutzer muss authentifiziert sein
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Nicht authentifiziert' });
    }

    try {
        // Hole aktuellen Benutzer
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Benutzer nicht gefunden' });
        }

        const user = result.rows[0];

        // Validiere aktuelles Passwort
        const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Aktuelles Passwort ist falsch' });
        }

        // Prüfe, ob neues Passwort gleich dem alten ist
        const sameAsOld = await bcrypt.compare(newPassword, user.password_hash);
        if (sameAsOld) {
            return res.status(400).json({ error: 'Neues Passwort darf nicht gleich dem alten sein' });
        }

        // Hash neues Passwort
        const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

        // Aktualisiere Passwort in DB
        await pool.query(
            'UPDATE users SET password_hash = $1 WHERE id = $2',
            [newPasswordHash, req.session.userId]
        );

        // Audit Log
        await logAudit(req.session.userId, 'CHANGE_PASSWORD', 'users', req.session.userId, `Passwort geändert von Benutzer ${user.username}`);

        res.json({ 
            success: true, 
            message: 'Passwort erfolgreich geändert. Bitte melden Sie sich erneut an.' 
        });

    } catch (error) {
        console.error('[CHANGE-PASSWORD] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Ändern des Passworts' });
    }
});

// ===== SERVER SSH-KEY MANAGEMENT =====

/**
 * POST /api/server-ssh-key/upload - Server-spezifischen SSH-Key hochladen
 */
app.post('/api/server-ssh-key/upload', async (req, res) => {
    const { hostname, key_content } = req.body;

    if (!hostname || !key_content) {
        return res.status(400).json({ error: 'hostname und key_content erforderlich' });
    }

    try {
        // Erstelle Verzeichnis für Server-spezifische Keys falls nicht vorhanden
        const serverKeysDir = path.join(SSH_KEYS_DIR, 'servers');
        if (!fs.existsSync(serverKeysDir)) {
            fs.mkdirSync(serverKeysDir, { recursive: true, mode: 0o700 });
        }

        // Speichere SSH-Key mit Hostname als Dateiname
        const keyFileName = `${hostname.replace(/[^a-zA-Z0-9.-]/g, '_')}-key`;
        const keyPath = path.join(serverKeysDir, keyFileName);

        // Schreibe Key mit restriktiven Berechtigungen
        fs.writeFileSync(keyPath, key_content, { mode: 0o600 });

        // Audit Log
        await logAudit(req.session?.userId || -1, 'UPLOAD_SERVER_SSH_KEY', 'backup_servers', hostname, `Key für ${hostname} hochgeladen`);

        res.json({
            success: true,
            message: 'SSH-Key erfolgreich hochgeladen',
            key_path: keyPath
        });
    } catch (error) {
        console.error('[SERVER-KEY] Fehler beim Hochladen:', error);
        res.status(500).json({ error: `Fehler beim Hochladen: ${error.message}` });
    }
});

// ===== BACKUP-SERVER ENDPUNKTE =====

/**
 * GET /api/servers - Alle Backup-Server auflisten
 */
app.get('/api/servers', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, hostname, ssh_port, ssh_user, status, created_at FROM backup_servers ORDER BY name'
        );
        res.json(result.rows);
    } catch (error) {
        console.error('[SERVERS] Fehler beim Abrufen:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Server' });
    }
});

/**
 * POST /api/servers - Neuen Backup-Server hinzufügen
 */
app.post('/api/servers', async (req, res) => {
    const { name, hostname, ssh_port, ssh_user, ssh_key_path, description } = req.body;

    if (!name || !hostname || !ssh_user || !ssh_key_path) {
        return res.status(400).json({ error: 'Erforderliche Felder fehlen' });
    }

    try {
        // Wenn ssh_key_path "DEFAULT" ist, nutze den globalen Default SSH-Key
        let finalKeyPath = ssh_key_path;
        if (ssh_key_path === 'DEFAULT') {
            finalKeyPath = DEFAULT_SSH_KEY_PATH;
            
            // Überprüfe ob Default SSH-Key existiert
            if (!fs.existsSync(DEFAULT_SSH_KEY_PATH)) {
                return res.status(400).json({ 
                    error: 'Default SSH-Key nicht konfiguriert. Bitte laden Sie einen SSH-Key im Admin-Bereich hoch.' 
                });
            }
        } else {
            // Bei custom Key: überprüfe ob die Datei existiert
            if (!fs.existsSync(ssh_key_path)) {
                return res.status(400).json({ 
                    error: 'SSH-Key Datei nicht gefunden: ' + ssh_key_path 
                });
            }
        }

        const result = await pool.query(
            'INSERT INTO backup_servers (name, hostname, ssh_port, ssh_user, ssh_key_path, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [name, hostname, ssh_port || 22, ssh_user, finalKeyPath, description]
        );

        // Audit Log
        await logAudit(req.session.userId, 'ADD_SERVER', 'backup_servers', result.rows[0].id, JSON.stringify(result.rows[0]));

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('[SERVERS] Fehler beim Hinzufügen:', error);
        res.status(500).json({ error: 'Fehler beim Hinzufügen des Servers' });
    }
});

/**
 * POST /api/addServerWithAuth - Server mit Default SSH-Key hinzufügen (Curl API - nicht passwortgeschützt)
 */
app.post('/api/addServerWithAuth', async (req, res) => {
    const { name, hostname, sshUsername, sshPort = 22, description = '' } = req.body;

    // Validiere Eingaben
    if (!name || !hostname || !sshUsername) {
        return res.status(400).json({ 
            error: 'Erforderliche Parameter fehlen: name, hostname, sshUsername' 
        });
    }

    try {
        // Überprüfe ob Default SSH-Key vorhanden ist
        if (!fs.existsSync(DEFAULT_SSH_KEY_PATH)) {
            return res.status(400).json({ 
                error: 'Default SSH-Key nicht konfiguriert. Bitte laden Sie einen SSH-Key im Admin-Bereich hoch.' 
            });
        }

        // Teste SSH-Verbindung mit Default SSH-Key
        const testCommand = `ssh -o "StrictHostKeyChecking=accept-new" -o ConnectTimeout=10 -o IdentityFile="${DEFAULT_SSH_KEY_PATH}" -p ${sshPort} ${sshUsername}@${hostname} "echo OK"`;
        
        console.log(`[ADDSERVER] Teste SSH-Verbindung für ${sshUsername}@${hostname}:${sshPort} mit Default-Key...`);

        await new Promise((resolve, reject) => {
            exec(testCommand, { timeout: 15000 }, (error, stdout, stderr) => {
                if (error) {
                    console.error(`[ADDSERVER-FEHLER] SSH-Verbindung zu ${hostname} fehlgeschlagen: ${stderr.trim()}`);
                    return reject(new Error(`SSH-Verbindung fehlgeschlagen: ${stderr.trim()}`));
                }
                console.log(`[ADDSERVER] SSH-Verbindung erfolgreich für ${hostname}`);
                resolve();
            });
        });

        // Versuche, Default SSH-Key zum Remote-Server zu kopieren
        const copyKeyCommand = `ssh-copy-id -o "StrictHostKeyChecking=accept-new" -i "${DEFAULT_SSH_KEY_PUB_PATH}" -p ${sshPort} ${sshUsername}@${hostname}`;

        console.log(`[ADDSERVER] Kopiere SSH-Key zu ${hostname}...`);

        await new Promise((resolve, reject) => {
            exec(copyKeyCommand, { timeout: 30000 }, (error, stdout, stderr) => {
                if (error) {
                    console.warn(`[ADDSERVER-WARN] SSH-Schlüsselkopie fehlgeschlagen (nicht kritisch): ${stderr.trim()}`);
                    // Nicht als Fehler behandeln, da der Server trotzdem hinzugefügt werden kann
                    return resolve();
                }
                console.log(`[ADDSERVER] SSH-Key erfolgreich kopiert für ${hostname}`);
                resolve();
            });
        });

        // Überprüfe ob Server bereits existiert
        const existingServer = await pool.query(
            'SELECT id FROM backup_servers WHERE hostname = $1',
            [hostname]
        );

        if (existingServer.rows.length > 0) {
            return res.status(409).json({ 
                error: 'Server mit diesem Hostname existiert bereits in der Datenbank.' 
            });
        }

        // Füge Server zu Datenbank hinzu (mit Default SSH-Key-Pfad)
        const result = await pool.query(
            'INSERT INTO backup_servers (name, hostname, ssh_port, ssh_user, ssh_key_path, description) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [name, hostname, sshPort, sshUsername, DEFAULT_SSH_KEY_PATH, description]
        );

        // Audit Log (mit Default-Benutzer für nicht authentifizierte Anfragen)
        const userId = req.session?.userId || -1;
        await logAudit(userId, 'ADD_SERVER_WITH_AUTH', 'backup_servers', result.rows[0].id, JSON.stringify({
            name: result.rows[0].name,
            hostname: result.rows[0].hostname,
            ssh_user: result.rows[0].ssh_user,
            timestamp: new Date().toISOString()
        }));

        console.log(`[ADDSERVER] Server ${hostname} erfolgreich mit ID ${result.rows[0].id} hinzugefügt.`);
        
        res.json({ 
            success: true, 
            id: result.rows[0].id,
            message: `Server ${hostname} erfolgreich hinzugefügt.`,
            server: result.rows[0]
        });

    } catch (error) {
        console.error(`[ADDSERVER-FEHLER] Fehler beim Hinzufügen des Servers ${hostname}: ${error.message}`);
        res.status(500).json({ 
            error: `Fehler beim Hinzufügen des Servers: ${error.message}` 
        });
    }
});

/**
 * DELETE /api/servers/:id - Server löschen
 */
app.delete('/api/servers/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        await pool.query('DELETE FROM backup_servers WHERE id = $1', [id]);
        await logAudit(req.session.userId, 'DELETE_SERVER', 'backup_servers', id, null);
        res.json({ success: true });
    } catch (error) {
        console.error('[SERVERS] Fehler beim Löschen:', error);
        res.status(500).json({ error: 'Fehler beim Löschen des Servers' });
    }
});

// ===== BACKUP-QUELLEN ENDPUNKTE =====

/**
 * GET /api/sources/:serverId - Backup-Quellen für einen Server
 */
app.get('/api/sources/:serverId', async (req, res) => {
    const { serverId } = req.params;

    try {
        const result = await pool.query(
            'SELECT id, server_id, name, remote_path, enabled, created_at FROM backup_sources WHERE server_id = $1 ORDER BY name',
            [serverId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('[SOURCES] Fehler beim Abrufen:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Quellen' });
    }
});

/**
 * POST /api/sources - Neue Backup-Quelle hinzufügen
 */
app.post('/api/sources', async (req, res) => {
    const { server_id, name, remote_path, description } = req.body;

    if (!server_id || !name || !remote_path) {
        return res.status(400).json({ error: 'Erforderliche Felder fehlen' });
    }

    try {
        const result = await pool.query(
            'INSERT INTO backup_sources (server_id, name, remote_path, description) VALUES ($1, $2, $3, $4) RETURNING *',
            [server_id, name, remote_path, description]
        );

        await logAudit(req.session.userId, 'ADD_SOURCE', 'backup_sources', result.rows[0].id, JSON.stringify(result.rows[0]));

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('[SOURCES] Fehler beim Hinzufügen:', error);
        res.status(500).json({ error: 'Fehler beim Hinzufügen der Quelle' });
    }
});

/**
 * DELETE /api/sources/:id - Quelle löschen
 */
app.delete('/api/sources/:id', requireAdmin, async (req, res) => {
    const { id } = req.params;

    try {
        await pool.query('DELETE FROM backup_sources WHERE id = $1', [id]);
        await logAudit(req.session.userId, 'DELETE_SOURCE', 'backup_sources', id, null);
        res.json({ success: true });
    } catch (error) {
        console.error('[SOURCES] Fehler beim Löschen:', error);
        res.status(500).json({ error: 'Fehler beim Löschen der Quelle' });
    }
});

// ===== BACKUP-SCHEDULES ENDPUNKTE =====

/**
 * GET /api/schedules/:sourceId - Schedules für eine Quelle
 */
app.get('/api/schedules/:sourceId', async (req, res) => {
    const { sourceId } = req.params;

    try {
        const result = await pool.query(
            'SELECT id, source_id, frequency, enabled, last_run, last_status, last_error_message FROM backup_schedules WHERE source_id = $1',
            [sourceId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('[SCHEDULES] Fehler beim Abrufen:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Schedules' });
    }
});

/**
 * POST /api/schedules - Neuen Schedule hinzufügen
 */
app.post('/api/schedules', async (req, res) => {
    const { source_id, frequency } = req.body;

    if (!source_id || !frequency) {
        return res.status(400).json({ error: 'Erforderliche Felder fehlen' });
    }

    const cronMap = {
        'hourly': '0 * * * *',
        'daily': '0 0 * * *',
        'weekly': '0 0 * * 0',
        'monthly': '0 0 1 * *'
    };

    try {
        const result = await pool.query(
            'INSERT INTO backup_schedules (source_id, frequency, cron_expression) VALUES ($1, $2, $3) RETURNING *',
            [source_id, frequency, cronMap[frequency]]
        );

        await logAudit(req.session.userId, 'ADD_SCHEDULE', 'backup_schedules', result.rows[0].id, JSON.stringify(result.rows[0]));

        // Starte Cron-Job
        await initBackupCronJob(result.rows[0].id);

        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('[SCHEDULES] Fehler beim Hinzufügen:', error);
        res.status(500).json({ error: 'Fehler beim Hinzufügen des Schedules' });
    }
});

// ===== BACKUP-JOBS ENDPUNKTE =====

/**
 * GET /api/jobs/:sourceId - Backup-Jobs für eine Quelle
 */
app.get('/api/jobs/:sourceId', async (req, res) => {
    const { sourceId } = req.params;
    const limit = req.query.limit || 100;

    try {
        const result = await pool.query(
            'SELECT id, source_id, status, job_date, archive_name, bytes_backed_up FROM backup_jobs WHERE source_id = $1 ORDER BY job_date DESC LIMIT $2',
            [sourceId, limit]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('[JOBS] Fehler beim Abrufen:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Jobs' });
    }
});

/**
 * POST /api/servers/:serverId/test-connection - SSH-Verbindung testen
 */
app.post('/api/servers/:serverId/test-connection', async (req, res) => {
    const { serverId } = req.params;

    try {
        const serverResult = await pool.query(
            'SELECT hostname, ssh_port, ssh_user, ssh_key_path FROM backup_servers WHERE id = $1',
            [serverId]
        );

        if (serverResult.rows.length === 0) {
            return res.status(404).json({ error: 'Server nicht gefunden' });
        }

        const server = serverResult.rows[0];

        // Akzeptiere Host-Key
        await acceptHostKey(server.hostname, server.ssh_port || 22);

        // Teste SSH-Verbindung
        const sshOpts = `-o IdentityFile="${server.ssh_key_path}" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${path.join(process.env.HOME || '/root', '.ssh', 'known_hosts')} -o ConnectTimeout=5`;
        const { stdout } = await execPromise(
            `ssh ${sshOpts} ${server.ssh_user}@${server.hostname} "echo 'SSH-Verbindung erfolgreich'"`
        );

        console.log(`[SSH-TEST] Erfolgreich für Server ${serverId}`);
        res.json({ success: true, message: 'SSH-Verbindung erfolgreich', output: stdout });
    } catch (error) {
        console.error(`[SSH-TEST] Fehler für Server ${serverId}:`, error);
        res.status(500).json({ 
            success: false, 
            error: 'SSH-Verbindung fehlgeschlagen',
            details: error.message
        });
    }
});

/**
 * POST /api/backup/manual/:sourceId - Manuelles Backup starten
 */
app.post('/api/backup/manual/:sourceId', async (req, res) => {
    const { sourceId } = req.params;

    try {
        // Hole Source und Server Informationen
        const sourceResult = await pool.query(
            'SELECT bs.id as server_id, bs.hostname, bs.ssh_port, bs.ssh_user, bs.ssh_key_path, bso.name as source_name, bso.remote_path FROM backup_sources bso JOIN backup_servers bs ON bso.server_id = bs.id WHERE bso.id = $1',
            [sourceId]
        );

        if (sourceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quelle nicht gefunden' });
        }

        const source = sourceResult.rows[0];

        // Starte Backup-Prozess im Hintergrund
        executeBackup(sourceId, source).catch(err => {
            console.error('[BACKUP] Fehler bei manuellem Backup:', err);
        });

        res.json({ success: true, message: 'Backup wird gestartet...' });
    } catch (error) {
        console.error('[BACKUP] Fehler beim Starten des Backups:', error);
        res.status(500).json({ error: 'Fehler beim Starten des Backups' });
    }
});

// ===== RECOVERY ENDPUNKTE =====

/**
 * GET /api/borg/archives/:sourceId - Liste aller Archive für eine Quelle
 */
app.get('/api/borg/archives/:sourceId', async (req, res) => {
    const { sourceId } = req.params;

    try {
        const sourceResult = await pool.query(
            'SELECT bs.id as server_id FROM backup_sources bso JOIN backup_servers bs ON bso.server_id = bs.id WHERE bso.id = $1',
            [sourceId]
        );
        
        if (sourceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quelle nicht gefunden' });
        }

        const server = sourceResult.rows[0];
        const repoPath = path.join(BACKUP_BASE_PATH, `server_${server.server_id}_source_${sourceId}`);

        try {
            const { stdout } = await execPromise(`borg list --json "${repoPath}"`, { maxBuffer: 50 * 1024 * 1024 });
            const data = JSON.parse(stdout);
            const archives = data.archives || [];
            res.json({ archives });
        } catch (borgError) {
            console.warn(`[RECOVERY] Borg list Fehler: ${borgError.message}`);
            res.json({ archives: [], warning: 'Leer oder nicht verfügbar' });
        }
    } catch (error) {
        console.error('[RECOVERY] Archive-Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Archive' });
    }
});

/**
 * GET /api/borg/files/:sourceId/:archiveName - Liste Dateien mit hierarchischer Ordnerstruktur
 */
app.get('/api/borg/files/:sourceId/:archiveName', async (req, res) => {
    const { sourceId, archiveName } = req.params;
    const folderPath = req.query.folder || ''; // z.B. /home/user oder ''

    try {
        const sourceResult = await pool.query(
            'SELECT bs.id as server_id FROM backup_sources bso JOIN backup_servers bs ON bso.server_id = bs.id WHERE bso.id = $1',
            [sourceId]
        );
        
        if (sourceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quelle nicht gefunden' });
        }

        const server = sourceResult.rows[0];
        const repoPath = path.join(BACKUP_BASE_PATH, `server_${server.server_id}_source_${sourceId}`);
        const decodedArchiveName = decodeURIComponent(archiveName);

        console.log(`[BORG] Listing files for archive: ${decodedArchiveName}, folder filter: "${folderPath}"`);

        // Erhöhe maxBuffer für große Archive (z.B. mit node_modules)
        const { stdout } = await execPromise(`borg list --json-lines "${repoPath}::${decodedArchiveName}"`, { maxBuffer: 50 * 1024 * 1024 });
        const allFiles = stdout.trim().split('\n').filter(line => line).map(line => {
            try { return JSON.parse(line); } catch (e) { return null; }
        }).filter(f => f !== null);

        console.log(`[BORG] Total files from archive: ${allFiles.length}`);

        // Baue hierarchische Struktur auf
        const rootPath = folderPath || '';
        const items = new Map();
        const folders = new Set();

        for (const file of allFiles) {
            let filePath = file.path || '';
            
            // Filtere nach aktuellem Ordner
            let shouldInclude = false;
            
            if (!rootPath) {
                // Root: zeige alle Dateien (wir filtern später auf direkte Kinder)
                shouldInclude = true;
            } else {
                // Subfolder: nur Dateien die mit rootPath/ anfangen
                if (filePath.startsWith(rootPath + '/')) {
                    shouldInclude = true;
                }
            }
            
            if (!shouldInclude) {
                continue;
            }
            
            // Jetzt berechne relative Pfad
            let relativePath;
            if (rootPath) {
                // Entferne rootPath aus dem Anfang
                if (filePath.startsWith(rootPath + '/')) {
                    relativePath = filePath.substring(rootPath.length + 1);
                } else {
                    continue;
                }
            } else {
                relativePath = filePath;
            }

            if (!relativePath) continue;

            const parts = relativePath.split('/').filter(p => p);
            if (parts.length === 0) continue;
            
            // Registriere parent folders
            let currentPath = rootPath ? rootPath : '';
            for (let i = 0; i < parts.length - 1; i++) {
                currentPath = currentPath ? currentPath + '/' + parts[i] : parts[i];
                folders.add(currentPath);
            }

            // Wenn das eine Datei/Ordner im direkten Ordner ist (parts.length === 1)
            if (parts.length === 1) {
                const fullPath = rootPath ? rootPath + '/' + parts[0] : parts[0];
                items.set(fullPath, {
                    path: fullPath,
                    name: parts[0],
                    type: file.type === 'd' ? 'directory' : 'file',
                    size: file.size || 0,
                    mtime: file.mtime,
                    isFolder: file.type === 'd'
                });
            } else {
                // Unterordner im aktuellen - nur den direkten Ordner anzeigen
                const firstDirPath = rootPath ? rootPath + '/' + parts[0] : parts[0];
                if (!items.has(firstDirPath)) {
                    items.set(firstDirPath, {
                        path: firstDirPath,
                        name: parts[0],
                        type: 'directory',
                        size: 0,
                        mtime: null,
                        isFolder: true
                    });
                }
            }
        }

        console.log(`[BORG] Files after filtering for folder "${folderPath}": ${items.size}`);

        // Sortiere: Ordner zuerst, dann Dateien
        const result = Array.from(items.values())
            .sort((a, b) => {
                if (a.isFolder !== b.isFolder) return a.isFolder ? -1 : 1;
                return a.name.localeCompare(b.name);
            });

        res.json({ 
            files: result,
            currentPath: folderPath
        });
    } catch (error) {
        console.error('[RECOVERY] Datei-Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Auflisten von Dateien' });
    }
});

/**
 * POST /api/borg/extract-folder/:sourceId/:archiveName - Ordner als ZIP herunterladen
 */
app.post('/api/borg/extract-folder/:sourceId/:archiveName', async (req, res) => {
    const { sourceId, archiveName } = req.params;
    const { folderPath } = req.body;

    if (!folderPath) {
        return res.status(400).json({ error: 'folderPath erforderlich' });
    }

    try {
        const sourceResult = await pool.query(
            'SELECT bs.id as server_id FROM backup_sources bso JOIN backup_servers bs ON bso.server_id = bs.id WHERE bso.id = $1',
            [sourceId]
        );
        
        if (sourceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quelle nicht gefunden' });
        }

        const server = sourceResult.rows[0];
        const repoPath = path.join(BACKUP_BASE_PATH, `server_${server.server_id}_source_${sourceId}`);
        const decodedArchiveName = decodeURIComponent(archiveName);
        
        const tmpDir = path.join('/tmp', `borg-extract-${Date.now()}-${sourceId}`);
        const zipName = path.basename(folderPath) || 'backup';

        // Erstelle temporäres Verzeichnis
        await execPromise(`mkdir -p "${tmpDir}"`);

        // Extrahiere den gesamten Ordner
        await execPromise(`cd "${tmpDir}" && borg extract "${repoPath}::${decodedArchiveName}" "${folderPath}"`, { maxBuffer: 50 * 1024 * 1024 });

        // Erstelle ZIP-Datei mit zip-Befehl
        const zipPath = path.join('/tmp', `${zipName}-${Date.now()}.zip`);
        const extractedPath = path.join(tmpDir, folderPath);

        if (!fs.existsSync(extractedPath)) {
            throw new Error('Ordner nach Extraktion nicht gefunden');
        }

        // Nutze zip-Befehl um Ordner zu komprimieren
        await execPromise(`cd "${tmpDir}" && zip -r "${zipPath}" "${folderPath}"`);

        // Download mit automatischer Bereinigung
        res.download(zipPath, `${zipName}.zip`, (err) => {
            try {
                fs.unlinkSync(zipPath);
                execPromise(`rm -rf "${tmpDir}"`).catch(() => {});
            } catch (e) {}
        });
    } catch (error) {
        console.error('[RECOVERY] Folder-Extract-Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Extrahieren des Ordners: ' + error.message });
    }
});

/**
 * POST /api/borg/extract/:sourceId/:archiveName - Datei extrahieren
 */
app.post('/api/borg/extract/:sourceId/:archiveName', async (req, res) => {
    const { sourceId, archiveName } = req.params;
    const { filePath } = req.body;

    if (!filePath) {
        return res.status(400).json({ error: 'filePath erforderlich' });
    }

    try {
        const sourceResult = await pool.query(
            'SELECT bs.id as server_id FROM backup_sources bso JOIN backup_servers bs ON bso.server_id = bs.id WHERE bso.id = $1',
            [sourceId]
        );
        
        if (sourceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quelle nicht gefunden' });
        }

        const server = sourceResult.rows[0];
        const repoPath = path.join(BACKUP_BASE_PATH, `server_${server.server_id}_source_${sourceId}`);
        const decodedArchiveName = decodeURIComponent(archiveName);
        const tmpDir = path.join('/tmp', `borg-extract-${Date.now()}`);

        await execPromise(`mkdir -p "${tmpDir}"`);
        await execPromise(`cd "${tmpDir}" && borg extract "${repoPath}::${decodedArchiveName}" "${filePath}"`, { maxBuffer: 50 * 1024 * 1024 });

        const fullPath = path.join(tmpDir, filePath);
        
        if (!fs.existsSync(fullPath)) {
            throw new Error('Datei nach Extraktion nicht gefunden');
        }

        res.download(fullPath, path.basename(filePath), () => {
            try { execPromise(`rm -rf "${tmpDir}"`).catch(() => {}); } catch (e) {}
        });
    } catch (error) {
        console.error('[RECOVERY] Extract-Fehler:', error);
        res.status(500).json({ error: 'Fehler bei der Extraktion' });
    }
});

/**
 * POST /api/borg/compact - Manuell alle Borg Repositories kompaktieren
 */
app.post('/api/borg/compact', requireAdmin, async (req, res) => {
    try {
        // Starte Kompaktierung asynchron im Hintergrund
        compactAllRepositories().catch(err => {
            console.error('[COMPACT] Fehler bei manuellem Compact:', err);
        });

        res.json({
            success: true,
            message: 'Kompaktierung aller Repositories gestartet. Dies kann einige Minuten dauern...'
        });
    } catch (error) {
        console.error('[COMPACT] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Starten der Kompaktierung' });
    }
});

/**
 * GET /api/recovery/:sourceId - Recovery-Dateien für eine Quelle auflisten
 */
app.get('/api/recovery/:sourceId', async (req, res) => {
    const { sourceId } = req.params;
    const jobId = req.query.jobId;

    try {
        let query = 'SELECT * FROM recovery_files WHERE backup_job_id IN (SELECT id FROM backup_jobs WHERE source_id = $1)';
        const params = [sourceId];

        if (jobId) {
            query += ' AND backup_job_id = $2';
            params.push(jobId);
        }

        query += ' ORDER BY file_path';

        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (error) {
        console.error('[RECOVERY] Fehler beim Abrufen:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Recovery-Dateien' });
    }
});

// ===== HILFSFUNKTIONEN =====

/**
 * Akzeptiert Host-Key vor der SSH-Verbindung automatisch
 */
async function acceptHostKey(hostname, ssh_port = 22) {
    try {
        // Nutze ssh-keyscan um den Host-Key zu erfassen und zu known_hosts hinzuzufügen
        const { stdout } = await execPromise(`ssh-keyscan -p ${ssh_port} ${hostname} 2>/dev/null`);
        if (stdout) {
            const knownHostsPath = path.join(process.env.HOME || '/root', '.ssh', 'known_hosts');
            const sshDir = path.dirname(knownHostsPath);
            
            // Stelle sicher, dass .ssh Verzeichnis existiert
            if (!fs.existsSync(sshDir)) {
                fs.mkdirSync(sshDir, { mode: 0o700 });
            }
            
            // Prüfe ob Host bereits in known_hosts
            try {
                const currentContent = fs.readFileSync(knownHostsPath, 'utf8');
                if (!currentContent.includes(hostname)) {
                    fs.appendFileSync(knownHostsPath, stdout);
                    console.log(`[SSH] Host-Key für ${hostname} akzeptiert`);
                }
            } catch (e) {
                // known_hosts existiert noch nicht
                fs.writeFileSync(knownHostsPath, stdout, { mode: 0o600 });
                console.log(`[SSH] known_hosts erstellt und Host-Key für ${hostname} hinzugefügt`);
            }
        }
    } catch (error) {
        console.warn(`[SSH] Konnte Host-Key für ${hostname} nicht automatisch akzeptieren:`, error.message);
        // Nicht kritisch - wir setzen SSH-Optionen zur Fallback
    }
}

/**
 * Führt ein Backup aus
 */
async function executeBackup(sourceId, source) {
    const jobId = await createBackupJob(sourceId);
    const repoPath = path.join(BACKUP_BASE_PATH, `server_${source.server_id}_source_${sourceId}`);

    try {
        console.log(`[BACKUP] Start für Source ${sourceId}`);

        // 1. Akzeptiere Host-Key automatisch (falls noch nicht bekannt)
        await acceptHostKey(source.hostname, source.ssh_port || 22);

        // 2. Initialisiere Borg Repository falls nötig
        if (!fs.existsSync(path.join(repoPath, "config"))) {
            await execPromise(`mkdir -p "${repoPath}"`);
            await execPromise(`borg init --encryption=none "${repoPath}"`);
        }

        // 3. Erstelle Archiv-Name
        const archiveName = `backup_${new Date().toISOString().replace(/:/g, '-')}`;
        
        // 4. Read-Only mit Sudo: Tar streamt Dateien, wird lokal extrahiert, dann zu Borg
        // Sudo wird NICHT zur Änderung der Berechtigungen verwendet, sondern nur zum LESEN
        const sshKeyOpt = source.ssh_key_path ? `-i "${source.ssh_key_path}"` : '';
        const knownHostsPath = path.join(process.env.HOME || '/root', '.ssh', 'known_hosts');
        const sshOpts = `-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=${knownHostsPath}`;
        
        // Escapte den Remote-Pfad für Shell-Sicherheit
        const escapedPath = source.remote_path.replace(/'/g, "'\\''");
        
        // Temp-Verzeichnis für Tar-Extraktion
        const tempDir = `/tmp/backup-${sourceId}-${Date.now()}`;
        
        // Tar mit Sudo auf Remote-Server
        const tarCommand = `ssh ${sshKeyOpt} ${sshOpts} ${source.ssh_user}@${source.hostname} "sudo tar -cf - '${escapedPath}' 2>/dev/null"`;
        
        // Erstelle Temp-Dir und extrahiere Tar dort hin
        console.log(`[BACKUP] Erstelle Temp-Verzeichnis: ${tempDir}`);
        await execPromise(`mkdir -p "${tempDir}"`);
        
        console.log(`[BACKUP] Extrahiere Tar-Stream von ${source.hostname}:${source.remote_path} nach ${tempDir}`);
        const extractCommand = `${tarCommand} | tar -xf - -C "${tempDir}"`;
        await execPromise(extractCommand);
        
        // Borg Backup des extrahierten Verzeichnisses mit voller Struktur
        const borgCommand = `borg create --progress --compression auto,zstd,10 --chunker-params 10,23,16,4095 "${repoPath}::${archiveName}" "${tempDir}"`;
        
        console.log(`[BACKUP] Backe extrahierte Dateien mit Borg`);
        const { stdout, stderr } = await execPromise(borgCommand);
        
        // Räume Temp-Verzeichnis auf
        console.log(`[BACKUP] Räume Temp-Verzeichnis auf`);
        await execPromise(`rm -rf "${tempDir}"`);

        // 5. Aktualisiere Job mit Erfolg
        await pool.query(
            'UPDATE backup_jobs SET status = $1, end_time = NOW(), archive_name = $2 WHERE id = $3',
            ['success', archiveName, jobId]
        );

        console.log(`[BACKUP] Erfolgreich abgeschlossen für Source ${sourceId}`);

    } catch (error) {
        console.error(`[BACKUP] Fehler für Source ${sourceId}:`, error.message);
        
        // Extrahiere Fehlerdetails aus stderr
        const errorDetails = error.stderr || error.message || 'Unbekannter Fehler beim Backup';
        
        await pool.query(
            'UPDATE backup_jobs SET status = $1, error_message = $2, end_time = NOW() WHERE id = $3',
            ['failed', errorDetails, jobId]
        );
    }
}

/**
 * Erstellt einen neuen Backup-Job
 */
async function createBackupJob(sourceId) {
    const result = await pool.query(
        'INSERT INTO backup_jobs (source_id, job_date, start_time, status) VALUES ($1, NOW(), NOW(), $2) RETURNING id',
        [sourceId, 'running']
    );
    return result.rows[0].id;
}

/**
 * Initialisiert einen Cron-Job
 */
async function initBackupCronJob(scheduleId) {
    try {
        const scheduleResult = await pool.query('SELECT * FROM backup_schedules WHERE id = $1', [scheduleId]);
        if (scheduleResult.rows.length === 0) return;

        const schedule = scheduleResult.rows[0];

        // Stoppe alten Job falls vorhanden
        if (cronJobs[scheduleId]) {
            cronJobs[scheduleId].stop();
        }

        // Starte neuen Cron-Job
        cronJobs[scheduleId] = cron.schedule(schedule.cron_expression, async () => {
            const sourceResult = await pool.query(
                'SELECT bs.id as server_id, bs.hostname, bs.ssh_port, bs.ssh_user, bs.ssh_key_path, bso.name as source_name, bso.remote_path FROM backup_sources bso JOIN backup_servers bs ON bso.server_id = bs.id WHERE bso.id = $1',
                [schedule.source_id]
            );

            if (sourceResult.rows.length > 0) {
                await executeBackup(schedule.source_id, sourceResult.rows[0]);
                await pool.query(
                    'UPDATE backup_schedules SET last_run = NOW(), last_status = $1 WHERE id = $2',
                    ['success', scheduleId]
                );
            }
        });

        console.log(`[CRON] Schedule ${scheduleId} initialisiert mit Ausdruck: ${schedule.cron_expression}`);
    } catch (error) {
        console.error('[CRON] Fehler beim Initialisieren:', error);
    }
}

/**
 * Audit-Log
 */
async function logAudit(userId, action, resourceType, resourceId, details) {
    try {
        await pool.query(
            'INSERT INTO audit_log (user_id, action, resource_type, resource_id, details) VALUES ($1, $2, $3, $4, $5)',
            [userId, action, resourceType, resourceId, details]
        );
    } catch (error) {
        console.error('[AUDIT] Fehler beim Logging:', error);
    }
}

// ===== ANWENDUNG STARTEN =====

/**
 * Kompaktiert alle Borg Repositories (inkrementelle Backups optimieren)
 */
async function compactAllRepositories() {
    try {
        console.log('[COMPACT] Starte Optimierung aller Repositories...');
        
        // Lese alle Verzeichnisse in BACKUP_BASE_PATH
        const repos = fs.readdirSync(BACKUP_BASE_PATH);
        let compactedCount = 0;
        
        for (const repoName of repos) {
            const repoPath = path.join(BACKUP_BASE_PATH, repoName);
            const stats = fs.statSync(repoPath);
            
            // Nur Verzeichnisse verarbeiten
            if (!stats.isDirectory()) continue;
            
            try {
                console.log(`[COMPACT] Optimiere Repository: ${repoName}`);
                const { stdout: compactOutput } = await execPromise(
                    `borg compact "${repoPath}"`
                );
                console.log(`[COMPACT] ✓ Erfolgreich: ${repoName}`);
                if (compactOutput) {
                    console.log(`[COMPACT]   ${compactOutput.trim()}`);
                }
                compactedCount++;
            } catch (error) {
                console.warn(`[COMPACT] ⚠ Fehler bei ${repoName}:`, error.message);
            }
        }
        
        console.log(`[COMPACT] Optimierung abgeschlossen: ${compactedCount}/${repos.length} Repositories erfolgreich`);
    } catch (error) {
        console.error('[COMPACT] Fehler beim Optimieren:', error);
    }
}

/**
 * Initialisiert alle Cron-Jobs aus der Datenbank und globale Maintenance-Jobs
 */
async function initializeAllCronJobs() {
    try {
        const result = await pool.query('SELECT id FROM backup_schedules WHERE enabled = TRUE');
        for (const schedule of result.rows) {
            await initBackupCronJob(schedule.id);
        }
        console.log(`[INIT] ${result.rows.length} Backup-Cron-Jobs initialisiert`);
        
        // Starte Compact-Job: Alle 6 Stunden (0 */6 * * *)
        cronJobs['compact'] = cron.schedule('0 */6 * * *', compactAllRepositories);
        console.log('[INIT] Compact-Job initialisiert (alle 6 Stunden)');
    } catch (error) {
        console.error('[INIT] Fehler beim Initialisieren der Cron-Jobs:', error);
    }
}

/**
 * Initialisiert erforderliche Ordnerstrukturen
 */
async function initializeFolderStructure() {
    try {
        const dirsToCreate = [
            { path: SSHFS_MOUNT_BASE, mode: 0o777, name: 'SSHFS Mount-Basis' },
            { path: BACKUP_BASE_PATH, mode: 0o777, name: 'Backup-Repository-Basis' },
            { path: SSH_KEYS_DIR, mode: 0o700, name: 'SSH-Keys-Verzeichnis' },
            { path: path.join(SSH_KEYS_DIR, 'servers'), mode: 0o700, name: 'Server SSH-Keys' }
        ];

        for (const dir of dirsToCreate) {
            if (!fs.existsSync(dir.path)) {
                try {
                    fs.mkdirSync(dir.path, { recursive: true, mode: dir.mode });
                    console.log(`[INIT] Verzeichnis erstellt: ${dir.path}`);
                } catch (error) {
                    if (error.code === 'EACCES') {
                        // Versuche mit sudo über Shell-Befehl
                        try {
                            await execPromise(`sudo mkdir -p "${dir.path}" && sudo chmod ${(dir.mode).toString(8)} "${dir.path}"`);
                            console.log(`[INIT] Verzeichnis mit sudo erstellt: ${dir.path}`);
                        } catch (sudoError) {
                            console.warn(`[INIT] ⚠️ Konnte nicht erstellen: ${dir.path}`);
                            console.warn(`[INIT] Bitte manuell ausführen: sudo mkdir -p "${dir.path}" && sudo chmod ${(dir.mode).toString(8)} "${dir.path}"`);
                        }
                    } else {
                        throw error;
                    }
                }
            } else {
                // Verzeichnis existiert bereits - stelle sicher, dass Berechtigungen korrekt sind
                try {
                    const stats = fs.statSync(dir.path);
                    const currentMode = stats.mode & parseInt('777', 8);
                    const requiredMode = dir.mode;
                    
                    // Wenn nicht SSH_KEYS_DIR (private), erhöhe Berechtigungen auf 777
                    if (dir.name.includes('Mount-Basis') || dir.name.includes('Repository-Basis')) {
                        if (currentMode !== requiredMode) {
                            try {
                                await execPromise(`sudo chmod ${requiredMode.toString(8)} "${dir.path}"`);
                                console.log(`[INIT] Berechtigungen korrigiert für: ${dir.path}`);
                            } catch (chmodError) {
                                console.warn(`[INIT] ⚠️ Konnte Berechtigungen nicht korrigieren: ${dir.path}`);
                            }
                        }
                    }
                } catch (statError) {
                    console.warn(`[INIT] Konnte Berechtigungen nicht prüfen für: ${dir.path}`);
                }
                console.log(`[INIT] Verzeichnis existiert bereits: ${dir.path}`);
            }
        }

        console.log('[INIT] Ordnerstruktur-Initialisierung abgeschlossen');
    } catch (error) {
        console.error('[INIT] Fehler beim Initialisieren der Ordnerstrukturen:', error);
        throw error;
    }
}

/**
 * Server starten
 */
async function startServer() {
    try {
        console.log('');
        console.log('╔════════════════════════════════════════════════════════════╗');
        console.log('║    🗄️  BBUI - Borg Backup Management System               ║');
        console.log('╚════════════════════════════════════════════════════════════╝');
        console.log('');
        
        console.log('⏳ Initialisiere Datenbank...');
        await initializeDatabase();
        
        console.log('⏳ Lade Konfiguration...');
        await loadConfiguration();
        
        console.log('⏳ Initialisiere Ordnerstruktur...');
        await initializeFolderStructure();
        
        console.log('⏳ Initialisiere Cron-Jobs...');
        await initializeAllCronJobs();

        app.listen(port, () => {
            console.log('');
            console.log('✅ Server erfolgreich gestartet!');
            console.log('');
            console.log(`   📍 URL:      http://localhost:${port}`);
            console.log('   👤 Benutzer: admin');
            console.log('   🔑 Passwort: admin');
            console.log('');
            console.log('   ⚠️  Ändern Sie das Passwort nach dem Login!');
            console.log('');
        });
    } catch (error) {
        console.error('[SERVER] ❌ Fehler beim Starten:', error);
        process.exit(1);
    }
}

startServer();

// Graceful Shutdown
process.on('SIGINT', () => {
    console.log('[SERVER] Fahre herunter...');
    Object.values(cronJobs).forEach(job => job.stop());
    pool.end();
    process.exit(0);
});

// ===== ERWEITERTE RECOVERY-FUNKTIONEN =====

/**
 * GET /api/backup-history/:sourceId - Vollständige Backup-Historie mit Details
 */
app.get('/api/backup-history/:sourceId', async (req, res) => {
    const { sourceId } = req.params;

    try {
        const result = await pool.query(
            `SELECT 
                bj.id, 
                bj.job_date, 
                bj.archive_name, 
                bj.status, 
                bj.bytes_backed_up,
                bj.repository_size,
                COUNT(rf.id) as file_count
            FROM backup_jobs bj
            LEFT JOIN recovery_files rf ON bj.id = rf.backup_job_id
            WHERE bj.source_id = $1
            GROUP BY bj.id
            ORDER BY bj.job_date DESC
            LIMIT 100`,
            [sourceId]
        );
        res.json(result.rows);
    } catch (error) {
        console.error('[RECOVERY] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Historie' });
    }
});

/**
 * GET /api/recovery-tree/:jobId - Dateibaum-Struktur für Restore
 */
app.get('/api/recovery-tree/:jobId', async (req, res) => {
    const { jobId } = req.params;

    try {
        const result = await pool.query(
            'SELECT file_path, file_type, file_size, modified_time FROM recovery_files WHERE backup_job_id = $1 ORDER BY file_path',
            [jobId]
        );

        // Baue Baumstruktur auf
        const tree = buildFileTree(result.rows);
        res.json(tree);
    } catch (error) {
        console.error('[RECOVERY] Fehler beim Abrufen des Baums:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Dateistruktur' });
    }
});

/**
 * POST /api/recovery-download/:jobId - Download von Dateien/Ordnern aus Backup
 */
app.post('/api/recovery-download/:jobId', async (req, res) => {
    const { jobId } = req.params;
    const { filePath } = req.body;

    if (!filePath) {
        return res.status(400).json({ error: 'Dateipfad erforderlich' });
    }

    try {
        // Hole Backup-Job-Details
        const jobResult = await pool.query(
            'SELECT * FROM backup_jobs WHERE id = $1',
            [jobId]
        );

        if (jobResult.rows.length === 0) {
            return res.status(404).json({ error: 'Backup nicht gefunden' });
        }

        const job = jobResult.rows[0];

        // Hole Source-Details für Repo-Pfad
        const sourceResult = await pool.query(
            'SELECT * FROM backup_sources WHERE id = $1',
            [job.source_id]
        );

        if (sourceResult.rows.length === 0) {
            return res.status(404).json({ error: 'Quelle nicht gefunden' });
        }

        const source = sourceResult.rows[0];
        const repoPath = path.join(BACKUP_BASE_PATH, `server_${source.server_id}_source_${source.id}`);

        // Restore-Verzeichnis erstellen
        const tempRestorePath = `/tmp/borg-restore-${jobId}-${Date.now()}`;
        await execPromise(`mkdir -p "${tempRestorePath}"`);

        try {
            // Extrahiere Datei/Ordner aus Borg
            await execPromise(
                `borg extract "${repoPath}::${job.archive_name}" "${filePath}" --progress`,
                { cwd: tempRestorePath }
            );

            // Sende Datei
            const fullPath = path.join(tempRestorePath, filePath);
            res.download(fullPath, path.basename(filePath), (err) => {
                if (err) console.error('[RECOVERY] Download-Fehler:', err);
                // Aufräumen
                execPromise(`rm -rf "${tempRestorePath}"`).catch(e => console.error('[CLEANUP] Fehler:', e));
            });
        } catch (error) {
            // Aufräumen bei Fehler
            await execPromise(`rm -rf "${tempRestorePath}"`).catch(() => {});
            throw error;
        }
    } catch (error) {
        console.error('[RECOVERY] Download-Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Download: ' + error.message });
    }
});

/**
 * Hilfsfunktion: Baue Baumstruktur aus flacher Liste
 */
function buildFileTree(files) {
    const tree = {};

    files.forEach(file => {
        const parts = file.file_path.split('/').filter(p => p.length > 0);
        let current = tree;

        parts.forEach((part, index) => {
            if (!current[part]) {
                current[part] = {};
            }

            if (index === parts.length - 1) {
                // Blatt-Knoten: Dateiinformationen
                current[part]._info = {
                    type: file.file_type,
                    size: file.file_size,
                    modified: file.modified_time,
                    path: file.file_path
                };
            }

            current = current[part];
        });
    });

    return tree;
}

// ===== STATUS & MONITORING =====

/**
 * GET /api/dashboard/stats - Dashboard-Statistiken mit Speicherplatz
 */
app.get('/api/dashboard/stats', async (req, res) => {
    try {
        const [servers, sources, jobs, latestBackups] = await Promise.all([
            pool.query('SELECT COUNT(*) as count FROM backup_servers WHERE enabled = TRUE'),
            pool.query('SELECT COUNT(*) as count FROM backup_sources WHERE enabled = TRUE'),
            pool.query('SELECT COUNT(*) as count FROM backup_jobs WHERE status = $1', ['success']),
            pool.query(`
                SELECT bs.name, bso.name as source_name, bj.job_date, bj.status
                FROM backup_jobs bj
                JOIN backup_sources bso ON bj.source_id = bso.id
                JOIN backup_servers bs ON bso.server_id = bs.id
                WHERE bj.status = 'success'
                ORDER BY bj.job_date DESC
                LIMIT 10
            `)
        ]);

        // Hole Speicherplatz-Informationen
        let storageStats = {
            used: 0,
            total: 0,
            available: 0,
            percentage: 0
        };

        try {
            const { stdout } = await execPromise(`df -B1 "${BACKUP_BASE_PATH}" | tail -1`);
            const parts = stdout.trim().split(/\s+/);
            if (parts.length >= 4) {
                const total = parseInt(parts[1]);
                const used = parseInt(parts[2]);
                const available = parseInt(parts[3]);
                storageStats = {
                    used,
                    total,
                    available,
                    percentage: Math.round((used / total) * 100)
                };
            }
        } catch (error) {
            console.warn('[STATS] Fehler beim Abrufen des Speicherplatzes:', error.message);
        }

        res.json({
            totalServers: servers.rows[0].count,
            totalSources: sources.rows[0].count,
            successfulBackups: jobs.rows[0].count,
            storage: storageStats,
            latestBackups: latestBackups.rows
        });
    } catch (error) {
        console.error('[STATS] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Statistiken' });
    }
});

/**
 * GET /api/dashboard - Vereinfachte Dashboard (Alias für /api/dashboard/stats)
 */
app.get('/api/dashboard', async (req, res) => {
    // Leite zur vollständigen Stats-API weiter
    const response = await fetch('http://localhost:8040/api/dashboard/stats');
    const data = await response.json();
    res.json(data);
});

/**
 * GET /api/server-status/:serverId - Status eines Servers
 */
app.get('/api/server-status/:serverId', async (req, res) => {
    const { serverId } = req.params;

    try {
        const result = await pool.query(
            `SELECT 
                bs.name,
                bs.hostname,
                COUNT(DISTINCT bso.id) as source_count,
                COUNT(DISTINCT bj.id) as backup_count,
                SUM(CASE WHEN bj.status = 'success' THEN bj.bytes_backed_up ELSE 0 END) as total_backed_up,
                MAX(CASE WHEN bj.status = 'success' THEN bj.job_date END) as last_successful_backup
            FROM backup_servers bs
            LEFT JOIN backup_sources bso ON bs.id = bso.server_id
            LEFT JOIN backup_jobs bj ON bso.id = bj.source_id
            WHERE bs.id = $1
            GROUP BY bs.id, bs.name, bs.hostname`,
            [serverId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Server nicht gefunden' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        console.error('[SERVER-STATUS] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen des Server-Status' });
    }
});

// ===== KONFIGURATION =====

/**
 * GET /api/config - Alle Konfigurationen abrufen
 */
app.get('/api/config', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT key, value, description FROM backup_config ORDER BY key');
        res.json(result.rows);
    } catch (error) {
        console.error('[CONFIG] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen der Konfiguration' });
    }
});

/**
 * PUT /api/config/:key - Konfiguration aktualisieren
 */
app.put('/api/config/:key', requireAdmin, async (req, res) => {
    const { key } = req.params;
    const { value } = req.body;

    try {
        const result = await pool.query(
            'UPDATE backup_config SET value = $1, updated_at = NOW() WHERE key = $2 RETURNING *',
            [value, key]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Konfiguration nicht gefunden' });
        }

        // Aktualisiere In-Memory-Konfiguration
        if (key === 'backup_base_path') {
            BACKUP_BASE_PATH = value;
            console.log(`[CONFIG] Backup-Pfad aktualisiert zu: ${BACKUP_BASE_PATH}`);
        }

        await logAudit(req.session.userId, 'UPDATE_CONFIG', 'backup_config', null, JSON.stringify(result.rows[0]));

        res.json(result.rows[0]);
    } catch (error) {
        console.error('[CONFIG] Fehler:', error);
        res.status(500).json({ error: 'Fehler beim Aktualisieren der Konfiguration' });
    }
});

// ===== SSH-KEY MANAGEMENT ENDPOINTS =====

/**
 * GET /api/admin/ssh-key-status - Status des Default SSH-Keys abrufen
 */
app.get('/api/admin/ssh-key-status', requireAdmin, async (req, res) => {
    try {
        const hasPrivateKey = fs.existsSync(DEFAULT_SSH_KEY_PATH);
        const hasPublicKey = fs.existsSync(DEFAULT_SSH_KEY_PUB_PATH);
        
        let fileStats = null;
        if (hasPrivateKey && hasPublicKey) {
            const stats = fs.statSync(DEFAULT_SSH_KEY_PATH);
            fileStats = {
                created: stats.birthtime,
                modified: stats.mtime,
                size: stats.size
            };
        }
        
        res.json({
            success: true,
            hasPrivateKey,
            hasPublicKey,
            fileStats,
            keyPath: DEFAULT_SSH_KEY_PATH
        });
    } catch (error) {
        console.error('[SSH-KEY] Fehler beim Abrufen des Status:', error);
        res.status(500).json({ error: 'Fehler beim Abrufen des Key-Status' });
    }
});

/**
 * POST /api/admin/ssh-key-upload - Default SSH-Key hochladen
 */
app.post('/api/admin/ssh-key-upload', requireAdmin, express.text({ type: '*/*', limit: '10mb' }), async (req, res) => {
    try {
        const keyContent = req.body;
        
        if (!keyContent || keyContent.length === 0) {
            return res.status(400).json({ error: 'Keine Key-Datei hochgeladen' });
        }
        
        // Überprüfe ob es ein valider SSH-Key ist
        // Akzeptiere:
        // 1. Private Keys mit "BEGIN" (RSA, OPENSSH, etc.)
        // 2. Public Keys die mit "ssh-" anfangen (ssh-rsa, ssh-ed25519, etc.)
        const isPrivateKey = keyContent.includes('BEGIN') || keyContent.includes('begin');
        const isPublicKey = keyContent.match(/^\s*ssh-/m) !== null; // Startet mit ssh-
        
        if (!isPrivateKey && !isPublicKey) {
            return res.status(400).json({ error: 'Ungültiges SSH-Key-Format. Erwartet wird ein SSH Private oder Public Key.' });
        }

        // Speichere Private Key oder Public Key
        if (isPrivateKey) {
            // Es ist ein Private Key
            fs.writeFileSync(DEFAULT_SSH_KEY_PATH, keyContent, { mode: 0o600 });
            console.log(`[SSH-KEY] Private Key hochgeladen und gespeichert`);
            
            // Versuche Public Key zu extrahieren
            const publicKeyMarkers = keyContent.match(/ssh-rsa AAAAB[A-Za-z0-9+\/=]+|ssh-ed25519 AAAA[A-Za-z0-9+\/=]+/);
            if (publicKeyMarkers && publicKeyMarkers[0]) {
                fs.writeFileSync(DEFAULT_SSH_KEY_PUB_PATH, publicKeyMarkers[0] + '\n', { mode: 0o644 });
                console.log(`[SSH-KEY] Public Key extrahiert und gespeichert`);
            }
        } else {
            // Es ist ein Public Key
            fs.writeFileSync(DEFAULT_SSH_KEY_PUB_PATH, keyContent, { mode: 0o644 });
            console.log(`[SSH-KEY] Public Key hochgeladen und gespeichert`);
            
            // Setze einen Platzhalter für Private Key (kann nicht aus Public Key erstellt werden)
            console.log(`[SSH-KEY] Hinweis: Nur Public Key vorhanden. Private Key nicht gespeichert.`);
        }

        res.json({ 
            success: true, 
            message: 'SSH-Key erfolgreich hochgeladen',
            privateKeyPath: DEFAULT_SSH_KEY_PATH,
            publicKeyPath: DEFAULT_SSH_KEY_PUB_PATH,
            keyType: isPrivateKey ? 'private' : 'public'
        });

    } catch (error) {
        console.error('[SSH-KEY] Fehler beim Hochladen:', error);
        res.status(500).json({ error: `Fehler beim Hochladen: ${error.message}` });
    }
});

/**
 * DELETE /api/admin/ssh-key - Default SSH-Key löschen
 */
app.delete('/api/admin/ssh-key', requireAdmin, async (req, res) => {
    try {
        if (fs.existsSync(DEFAULT_SSH_KEY_PATH)) {
            fs.unlinkSync(DEFAULT_SSH_KEY_PATH);
            console.log(`[SSH-KEY] Private Key gelöscht`);
        }
        
        if (fs.existsSync(DEFAULT_SSH_KEY_PUB_PATH)) {
            fs.unlinkSync(DEFAULT_SSH_KEY_PUB_PATH);
            console.log(`[SSH-KEY] Public Key gelöscht`);
        }
        
        res.json({ success: true, message: 'SSH-Key erfolgreich gelöscht' });
    } catch (error) {
        console.error('[SSH-KEY] Fehler beim Löschen:', error);
        res.status(500).json({ error: 'Fehler beim Löschen des Keys' });
    }
});

/**
 * GET /api/admin/ssh-key-download - Default SSH-Key herunterladen (nur Private Key)
 */
app.get('/api/admin/ssh-key-download', requireAdmin, (req, res) => {
    try {
        if (!fs.existsSync(DEFAULT_SSH_KEY_PATH)) {
            return res.status(404).json({ error: 'SSH-Key nicht vorhanden' });
        }
        
        res.download(DEFAULT_SSH_KEY_PATH, 'default-key', (err) => {
            if (err && err.code !== 'ERR_HTTP_HEADERS_SENT') {
                console.error('[SSH-KEY] Fehler beim Download:', err);
            }
        });
    } catch (error) {
        console.error('[SSH-KEY] Fehler beim Download:', error);
        res.status(500).json({ error: 'Fehler beim Download des Keys' });
    }
});
