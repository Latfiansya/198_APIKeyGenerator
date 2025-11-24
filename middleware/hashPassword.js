const bcrypt = require('bcryptjs');

async function hashPassword(req, res, next) {
    const { password } = req.body;

    if (!password) {
        return res.status(400).json({
        success: false,
        message: "Password wajib dikirim."
        });
    }

    try {
        const hashed = await bcrypt.hash(password, 10);
        req.hashedPassword = hashed; // disimpan untuk route berikutnya
        next();
    } catch (err) {
        console.error("Gagal hash password:", err);
        res.status(500).json({ success: false, message: "Kesalahan server." });
    }
}

module.exports = hashPassword;
