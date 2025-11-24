// server.js
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const app = express();
const bcrypt = require('bcrypt');

const PORT = 3000;

// --- Inisialisasi Database SQLite ---
const db = new sqlite3.Database('./apikeys.db', (err) => {
  if (err) console.error('Gagal konek database:', err);
  else console.log('Terkoneksi ke database SQLite.');
});

// Buat tabel kalau belum ada
db.run(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// --- Middleware ---
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

// --- Routes ---

// Root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Route untuk mendaftar admin baru
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

// Route untuk login admin
app.post('/admin/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM admin WHERE email = ?`, [email], async (err, admin) => {
        if (!admin) return res.status(401).json({ success: false, message: "Email tidak ditemukan" });

        const valid = await bcrypt.compare(password, admin.password);
        if (!valid) return res.status(401).json({ success: false, message: "Password salah" });

        res.json({ success: true, message: "Login berhasil" });
    });
});

// Route untuk dashboard admin
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

        res.json({
            success: true,
            data: rows
        });
    });
});


// Route untuk membuat API key baru & simpan ke DB
app.post('/create', (req, res) => {
  try {
    const randomKey = 'sk-' + crypto.randomBytes(24).toString('base64url');

    // Simpan ke database
    db.run(`INSERT INTO api_keys (key) VALUES (?)`, [randomKey], (err) => {
      if (err) {
        console.error('Gagal menyimpan ke database:', err);
        return res.status(500).json({
          success: false,
          message: 'Gagal menyimpan API key ke database.'
        });
      }

      res.status(200).json({
        success: true,
        apiKey: randomKey,
        message: 'API key berhasil digenerate dan disimpan ke database!'
      });
    });
  } catch (err) {
    console.error('Error saat generate:', err);
    res.status(500).json({
      success: false,
      message: 'Terjadi kesalahan saat membuat API key.'
    });
  }
});

// Route untuk cek API key di database
app.post('/cekapi', (req, res) => {
  const { apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({
      success: false,
      message: 'API key belum dikirim dalam body request.'
    });
  }

  db.get(`SELECT * FROM api_keys WHERE key = ?`, [apiKey], (err, row) => {
    if (err) {
      console.error('Gagal cek database:', err);
      return res.status(500).json({
        success: false,
        message: 'Terjadi kesalahan saat cek database.'
      });
    }

    if (row) {
      // Catat log pemakaian API key
    db.run(
        `INSERT INTO api_usage_log (api_key_id) VALUES (?)`,
        [row.id]
    );
    return res.status(200).json({
        success: true,
        message: 'API key valid.'
    });
    } else {
      res.status(401).json({ success: false, message: 'API key tidak valid.' });
    }
  });
});

// Route untuk menyimpan data user (wajib punya API key yang valid)
app.post('/user/save', (req, res) => {
  const { firstName, lastName, email, apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({
      success: false,
      message: "Harus generate API key terlebih dahulu."
    });
  }

  // Ambil id api_key dari tabel api_keys
  db.get(`SELECT id FROM api_keys WHERE key = ?`, [apiKey], (err, row) => {
    if (err || !row) {
      return res.status(400).json({
        success: false,
        message: "API key tidak ditemukan di database."
      });
    }

    const apiKeyId = row.id;

    db.run(
      `INSERT INTO user (firstName, lastName, email, api_key_id)
       VALUES (?, ?, ?, ?)`,
      [firstName, lastName, email, apiKeyId],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).json({
            success: false,
            message: "Gagal menyimpan data user."
          });
        }

        return res.status(200).json({
          success: true,
          message: "User berhasil disimpan!"
        });
      }
    );
  });
});



// --- Jalankan server ---
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});