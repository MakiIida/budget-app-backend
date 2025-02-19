require('dotenv').config(); // Lataa ympäristömuuttujat
console.log("DATABASE_URL:", process.env.DATABASE_URL); // Tarkista, latautuuko se oikein

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg'); // PostgreSQL-yhteys
const { body, validationResult } = require('express-validator'); // Validointi
const bcrypt = require('bcryptjs'); // Salasanojen hashaus
const jwt = require('jsonwebtoken'); // Tokenien luominen

const app = express();
app.use(cors());
app.use(express.json());

// const secretKey = process.env.JWT_SECRET || "salainen_avain"; // JWT-salasana

const secretKey = process.env.JWT_SECRET;
if (!secretKey) {
    console.error("❌ JWT_SECRET puuttuu ympäristömuuttujista!");
    process.exit(1);
}

// Luo tietokantayhteys Renderiin
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Render vaatii SSL-yhteyden
});

// **Testataan tietokantayhteys heti palvelimen käynnistyessä**
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error("⚠️ Tietokantayhteys epäonnistui:", err.message);
  } else {
    console.log("✅ Tietokantayhteys toimii! Aika:", res.rows[0].now);
  }
});

// **Pääreitti**
app.get('/', (req, res) => {
  res.send('Budjettisovellus API toimii!');
});

// **Testaa tietokantayhteyttä selaimessa**
app.get('/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ success: true, time: result.rows[0] });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// **Middleware JWT-tokenin tarkistukseen**
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
      return res.status(401).json({ success: false, error: "Pääsy estetty: Token puuttuu" });
  }

  const token = authHeader.split(' ')[1];
  jwt.verify(token, secretKey, (err, user) => {
      if (err) {
          return res.status(403).json({ success: false, error: "Virheellinen token" });
      }
      console.log("JWT-käyttäjä:", user);
      req.user = user;
      next();
  });
};

// **Rekisteröi uusi käyttäjä**
app.post('/register', [
  body('name').notEmpty().withMessage('Nimi ei voi olla tyhjä'),
  body('email').isEmail().withMessage('Anna kelvollinen sähköpostiosoite'),
  body('password').isLength({ min: 6 }).withMessage('Salasanan tulee olla vähintään 6 merkkiä pitkä')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  try {
    const { name, email, password } = req.body;

    // Tarkista, onko käyttäjä jo olemassa
    const userExists = await pool.query('SELECT * FROM public."users" WHERE email = $1', [email]);
    if (userExists.rows.length > 0) {
      return res.status(400).json({ success: false, error: "Sähköposti on jo käytössä" });
    }

    // Hashataan salasana
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Tallennetaan uusi käyttäjä tietokantaan
    const result = await pool.query(
      'INSERT INTO public."users" (name, email, password, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id, name, email, created_at',
      [name, email, hashedPassword]
    );

    res.status(201).json({ success: true, user: result.rows[0] });

  } catch (error) {
    console.error("❌ Virhe rekisteröinnissä:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// **Kirjautuminen (POST /login)**
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
      const result = await pool.query('SELECT * FROM public.users WHERE email = $1', [email]);

      if (result.rows.length === 0) {
          return res.status(401).json({ success: false, error: "Virheellinen sähköposti tai salasana" });
      }

      const user = result.rows[0];

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
          return res.status(401).json({ success: false, error: "Virheellinen sähköposti tai salasana" });
      }

      const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: '1h' });

      res.json({ success: true, token });
  } catch (error) {
      console.error("❌ Virhe kirjautumisessa:", error.message);
      res.status(500).json({ success: false, error: error.message });
  }
});

// **Hae kaikki käyttäjät (vain kirjautuneille käyttäjille)**
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, created_at FROM public."users"');
    res.json(result.rows);
  } catch (error) {
    console.error("❌ Virhe haettaessa käyttäjiä:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// **Hae kirjautunut käyttäjä (/me-reitti)**
app.get('/me', authenticateToken, async (req, res) => {
  try {
    console.log("Kirjautuneen käyttäjän ID:", req.user.id);
    const result = await pool.query('SELECT id, name, email FROM public."users" WHERE id = $1', [req.user.id]);
    console.log("Käyttäjän tietokanta vastaus:", result.rows);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Käyttäjää ei löydy" });
    }
    res.json(result.rows[0]);
  } catch (error) {
    console.error("❌ Virhe käyttäjän hakemisessa:", error.message);
    res.status(500).json({ error: "Virhe käyttäjän hakemisessa" });
  }
});

// **Lisää uusi käyttäjä (validoinnilla)**
app.post('/users', [
  body('name').notEmpty().withMessage('Nimi ei voi olla tyhjä'),
  body('email').isEmail().withMessage('Anna kelvollinen sähköpostiosoite')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  try {
    const { name, email } = req.body;
    const result = await pool.query(
      'INSERT INTO public.users (name, email, created_at) VALUES ($1, $2, NOW()) RETURNING *',
      [name, email]
    );
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    console.error("❌ Virhe lisättäessä käyttäjää:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// **Päivitä käyttäjän tiedot (validoinnilla)**
app.put('/users/:id', [
  body('name').notEmpty().withMessage('Nimi ei voi olla tyhjä'),
  body('email').isEmail().withMessage('Anna kelvollinen sähköpostiosoite')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

  const { id } = req.params; // Käyttäjän ID URL:sta
  const { name, email } = req.body; // Uudet tiedot pyynnöstä

  try {
    const result = await pool.query(
      'UPDATE public."users" SET name = $1, email = $2 WHERE id = $3 RETURNING *',
      [name, email, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Käyttäjää ei löydy" });
    }

    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// **Poista käyttäjä (vain kirjautuneille)**
app.delete('/users/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM public."users" WHERE id = $1 RETURNING *', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Käyttäjää ei löydy" });
    }

    res.json({ success: true, message: "Käyttäjä poistettu", user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// **Aseta palvelimen portti**
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));


