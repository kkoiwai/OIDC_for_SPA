const sqlite3 = require('sqlite3'),
    db = new sqlite3.Database('oidc_db.sqlite');
db.serialize();

// Create session table
db.run('DROP TABLE IF EXISTS session');
db.run("CREATE TABLE session (session_id TEXT UNIQUE NOT NULL, pkce_code TEXT, subject_id TEXT, user_info TEXT, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (DATETIME('now', 'localtime')))");

db.close();

