// server.js
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const app = express();

const PORT = 3000;

// --- Inisialisasi Database SQLite ---
const db = new sqlite3.Database('./apikeys.db', (err) => {
  if (err) console.error('Gagal konek database:', err);
  else console.log('Terkoneksi ke database SQLite.');
});

// --- Buat tabel bila belum ada ---
db.run(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    api_key_id INTEGER,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
  )
`);

db.run(`
  CREATE TABLE IF NOT EXISTS api_usage_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id INTEGER NOT NULL,
    checked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
  )
`);

// --- Middleware ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// ================================
// ROUTES
// ================================

// Halaman utama
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// -----------------------
// ADMIN REGISTER
// -----------------------
app.post('/admin/register', async (req, res) => {
  const { email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO admin (email, password) VALUES (?, ?)`,
    [email, hash],
    (err) => {
      if (err) {
        return res.status(500).json({ success: false, message: "Gagal daftar admin." });
      }
      res.json({ success: true, message: "Admin berhasil terdaftar." });
    }
  );
});

// -----------------------
// ADMIN LOGIN
// -----------------------
app.post('/admin/login', (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM admin WHERE email = ?`, [email], async (err, admin) => {
    if (!admin) return res.status(401).json({ success: false, message: "Email tidak ditemukan" });

    const valid = await bcrypt.compare(password, admin.password);
    if (!valid) return res.status(401).json({ success: false, message: "Password salah" });

    res.json({ success: true, message: "Login berhasil" });
  });
});

// -----------------------
// ADMIN DASHBOARD
// -----------------------
app.get('/admin/dashboard', (req, res) => {
  const sql = `
    SELECT u.firstName, u.lastName, u.email, k.key,
    CASE 
      WHEN EXISTS (
          SELECT 1 FROM api_usage_log 
          WHERE api_key_id = k.id 
          AND checked_at >= DATETIME('now', '-30 days')
      )
      THEN 'online'
      ELSE 'offline'
    END AS status
    FROM user u
    JOIN api_keys k ON u.api_key_id = k.id
  `;

  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).json({ success: false });

    res.json({ success: true, data: rows });
  });
});

// -----------------------
// GENERATE API KEY
// -----------------------
app.post('/create', (req, res) => {
  try {
    const randomKey = 'sk-' + crypto.randomBytes(24).toString('base64url');

    db.run(`INSERT INTO api_keys (key) VALUES (?)`, [randomKey], (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({
          success: false,
          message: 'Gagal menyimpan API key ke database.'
        });
      }

      res.json({
        success: true,
        apiKey: randomKey,
        message: 'API key berhasil digenerate dan disimpan ke database!'
      });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: "Terjadi kesalahan." });
  }
});

// -----------------------
// CHECK API KEY
// -----------------------
app.post('/cekapi', (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey) {
    return res.status(400).json({
      success: false,
      message: 'API key belum dikirim.'
    });
  }

  db.get(`SELECT * FROM api_keys WHERE key = ?`, [apiKey], (err, row) => {
    if (err) return res.status(500).json({ success: false });

    if (row) {
      db.run(`INSERT INTO api_usage_log (api_key_id) VALUES (?)`, [row.id]);
      return res.json({ success: true, message: 'API key valid.' });
    }

    res.status(401).json({ success: false, message: 'API key tidak valid.' });
  });
});

// -----------------------
// SIMPAN USER
// -----------------------
app.post('/user/save', (req, res) => {
  const { firstName, lastName, email, apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({
      success: false,
      message: "Harus generate API key terlebih dahulu."
    });
  }

  db.get(`SELECT id FROM api_keys WHERE key = ?`, [apiKey], (err, row) => {
    if (err || !row) {
      return res.status(400).json({
        success: false,
        message: "API key tidak ditemukan."
      });
    }

    const apiKeyId = row.id;

    db.run(
      `INSERT INTO user (firstName, lastName, email, api_key_id)
       VALUES (?, ?, ?, ?)`,
      [firstName, lastName, email, apiKeyId],
      function (err) {
        if (err) {
          return res.status(500).json({
            success: false,
            message: "Gagal menyimpan user."
          });
        }

        res.json({ success: true, message: "User berhasil disimpan!" });
      }
    );
  });
});

// --- Jalankan server ---
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
