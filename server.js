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

// **Lisää käyttäjän tulot ja menot**
app.post('/api/budgets', authenticateToken, async (req, res) => {
  try {
      // Haetaan tiedot pyynnöstä
      const { month, year, income, actualIncome, expenses } = req.body;
      const user_id = req.user.id; // Haetaan käyttäjän ID tokenista

      if (!user_id) {
          return res.status(400).json({ success: false, error: "Käyttäjän ID puuttuu" });
      }

      // Tarkista, onko käyttäjällä jo budjetti tälle kuukaudelle ja vuodelle
      const existingBudget = await pool.query(
        'SELECT * FROM budgets WHERE user_id = $1 AND kuukausi = $2 AND vuosi = $3',
        [user_id, month, year]
      );

      if (existingBudget.rows.length > 0) {
        return res.status(400).json({ success: false, error: "Budjetti tälle kuukaudelle on jo olemassa" });
      }

      // Lasketaan menojen kokonaismäärä ja pyöristetään 2 desimaaliin
      const total_expenses = Object.values(expenses)
          .map(v => v ? parseFloat(v) || 0 : 0) // Muutetaan arvot numeroiksi tai asetetaan 0, jos tyhjä
          .reduce((a, b) => a + b, 0) // Summataan kaikki luvut
          .toFixed(2); // Pyöristetään 2 desimaaliin
      
      // Tallennetaan budjetti tietokantaan
      const result = await pool.query(
          `INSERT INTO budgets (
              user_id, kuukausi, vuosi, 
              suunniteltu_tulot, toteutunut_tulot, 
              suunniteltu_menot, toteutunut_menot, 
              created_at, updated_at
          ) 
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) 
          RETURNING *`,
          [
              user_id, 
              month, 
              year, 
              income !== undefined && income !== "" ? parseFloat(income) : null, // NULL jos tyhjä
              actualIncome !== undefined && actualIncome !== "" ? parseFloat(actualIncome) : null, // NULL jos tyhjä
              total_expenses !== undefined && total_expenses !== "" ? parseFloat(total_expenses) : null, // NULL jos tyhjä
              0, // Toteutuneet menot oletuksena 0 (voit myös muuttaa null)
              new Date(), 
              new Date()
          ]
        );

        res.status(201).json({ success: true, budget: result.rows[0] });

  } catch (error) {
      console.error("❌ Virhe tallennettaessa budjettia:", error.message);
      res.status(500).json({ error: 'Tietokantavirhe' });
  }
});

// TÄMÄ LISÄTTY TESTINÄ!!!
app.post('/api/transactions', authenticateToken, async (req, res) => {
  try {
      const { budget_id, tyyppi, summa, kuvaus } = req.body;
      const user_id = req.user.id; // Haetaan käyttäjän ID tokenista

      // Tarkistetaan, että kaikki pakolliset kentät on annettu
      if (!budget_id || !tyyppi || summa === undefined || kuvaus === undefined) {
          return res.status(400).json({ error: "Kaikki kentät ovat pakollisia" });
      }

      const result = await pool.query(
          `INSERT INTO transactions (budget_id, user_id, tyyppi, summa, kuvaus, created_at, updated_at) 
           VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) 
           RETURNING *`,
          [budget_id, user_id, tyyppi, summa, kuvaus]
      );

      res.status(201).json({ success: true, transaction: result.rows[0] });
  } catch (error) {
      console.error("❌ Virhe lisättäessä tapahtumaa:", error.message);
      res.status(500).json({ error: "Tietokantavirhe" });
  }
});
// PÄÄTTYEN TÄHÄN!!!

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

// **Poista kirjautunut käyttäjä (vain itsensä)**
app.delete('/me', authenticateToken, async (req, res) => {
  const userId = req.user.id; // Haetaan käyttäjän ID tokenista

  try {
    // Poistetaan käyttäjä tietokannasta
    const result = await pool.query('DELETE FROM public."users" WHERE id = $1 RETURNING *', [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: "Käyttäjää ei löydy" });
    }

    res.json({ success: true, message: "Käyttäjätiedot poistettu onnistuneesti" });
  } catch (error) {
    console.error("❌ Virhe käyttäjän poistamisessa:", error.message);
    res.status(500).json({ success: false, error: "Virhe käyttäjän poistamisessa" });
  }
});

// **Poista budjetti**
app.delete('/api/budgets/:id', authenticateToken, async (req, res) => {
  try {
      const { id } = req.params;
      const userId = req.user.id; // Käyttäjän ID tokenista

      // Tarkistetaan, kuuluuko budjetti käyttäjälle
      const result = await pool.query(
          'DELETE FROM budgets WHERE id = $1 AND user_id = $2 RETURNING *',
          [id, userId]
      );

      if (result.rows.length === 0) {
          return res.status(404).json({ success: false, error: "Budjettia ei löytynyt tai sinulla ei ole oikeuksia poistaa sitä" });
      }

      res.json({ success: true, message: "Budjetti poistettu onnistuneesti" });

  } catch (error) {
      console.error("❌ Virhe budjetin poistamisessa:", error.message);
      res.status(500).json({ success: false, error: "Virhe budjetin poistamisessa" });
  }
});

// **Hae kaikki budjetit (vain kirjautuneille käyttäjille)**
app.get('/api/budgets', authenticateToken, async (req, res) => {
  try {
      const result = await pool.query(
          'SELECT id, user_id, kuukausi AS month, vuosi AS year, suunniteltu_tulot AS income, suunniteltu_menot AS expenses FROM budgets WHERE user_id = $1 ORDER BY created_at DESC', 
          [req.user.id]
      );

      res.json(result.rows.map(budget => ({
          ...budget,
          total: budget.income - budget.expenses // Lasketaan budjetin saldo
      })));
  } catch (error) {
      console.error("❌ Virhe budjettien hakemisessa:", error.message);
      res.status(500).json({ success: false, error: "Virhe budjettien hakemisessa" });
  }
});

app.get('/api/categories', async (req, res) => {
  try {
      const result = await pool.query('SELECT * FROM categories ORDER BY id ASC');
      res.json(result.rows);
  } catch (error) {
      console.error("❌ Virhe haettaessa kategorioita:", error);
      res.status(500).json({ error: "Tietokantavirhe" });
  }
});

// TÄMÄ LISÄTTY TESTINÄ!!!
app.get("/api/transactions/:budgetId", async (req, res) => {
  const { budgetId } = req.params;
  
  try {
    const transactions = await pool.query(
      "SELECT * FROM transactions WHERE budget_id = $1",
      [budgetId]
    );
    res.json(transactions.rows);
  } catch (error) {
    console.error("❌ Virhe haettaessa tapahtumia:", error);
    res.status(500).json({ error: "Virhe haettaessa tapahtumia" });
  }
});
// TESTI PÄÄTTYY TÄHÄN!!!

// **Hae yksittäinen budjetti ID:llä**
app.get('/api/budgets/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id; // Haetaan käyttäjän ID tokenista

    console.log("🔍 Haetaan budjetti ID:", id, "käyttäjälle", userId); 

    // 🔹 Haetaan budjetin perustiedot
    const budgetResult = await pool.query(
      `SELECT id, user_id, kuukausi AS month, vuosi AS year, 
              suunniteltu_tulot AS income, toteutunut_tulot AS actual_income, 
              suunniteltu_menot AS planned_expenses, toteutunut_menot AS actual_expenses
      FROM budgets 
      WHERE id = $1 AND user_id = $2`, 
      [id, userId]
    );

    console.log("✅ Budjetti haettu onnistuneesti:", budgetResult.rows); // OIKEASSA PAIKASSA NYT

    // Jos budjettia ei löytynyt tai käyttäjällä ei ole oikeuksia
    if (budgetResult.rows.length === 0) {
      return res.status(404).json({ error: "Budjettia ei löytynyt tai sinulla ei ole oikeuksia nähdä sitä" });
    }

    // Palautetaan pelkkä budjetin data ilman "expenses"-taulua
    res.json(budgetResult.rows[0]); 

  } catch (error) {
    console.error("❌ Virhe haettaessa budjettia:", error.message);
    res.status(500).json({ error: "Virhe budjetin hakemisessa" });
  }
});

// **Aseta palvelimen portti**
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
