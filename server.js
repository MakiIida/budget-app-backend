require('dotenv').config(); // Lataa ympäristömuuttujat

const express = require('express'); // Ladataan Express.js
const cors = require('cors'); // Otetaan käyttöön CORS
const { Pool } = require('pg'); // PostgreSQL-yhteys
const { body, validationResult } = require('express-validator'); // Validointi
const bcrypt = require('bcryptjs'); // Salasanojen hashaus
const jwt = require('jsonwebtoken'); // Tokenien luominen

const app = express();
app.use(cors());
app.use(express.json());

const secretKey = process.env.JWT_SECRET;
if (!secretKey) {
    console.error(" JWT_SECRET puuttuu ympäristömuuttujista!");
    process.exit(1);
}

// Luo tietokantayhteys Renderiin
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Testataan tietokantayhteys heti palvelimen käynnistyessä
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error("Tietokantayhteys epäonnistui:", err.message);
  } else {
    console.log("Tietokantayhteys toimii! Aika:", res.rows[0].now);
  }
});

// Pääreitti
app.get('/', (req, res) => {
  res.send('Budjettisovellus API toimii!');
});

// Testaa tietokantayhteyttä selaimessa
app.get('/test-db', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ success: true, time: result.rows[0] });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

// Middleware JWT-tokenin tarkistukseen
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];

  if (!token) {
      return res.status(403).json({ error: "Ei lupaa, kirjautuminen vaaditaan." });
  }

  jwt.verify(token, secretKey, (err, user) => {
      if (err) {
          return res.status(403).json({ error: "Virheellinen token." });
      }
      req.user = user;
      next();
  });
};

// Rekisteröi uusi käyttäjä
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
      return res.status(400).json({ error: "Kaikki kentät ovat pakollisia!" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  try {
      const result = await pool.query(
          "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email",
          [name, email, hashedPassword]
      );

      const user = result.rows[0];
      const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: "1h" });

      res.json({ token, user });

  } catch (error) {
      console.error("Virhe rekisteröinnissä:", error);
      res.status(500).json({ error: "Käyttäjän luominen epäonnistui." });
  }
});

// Kirjautuminen (POST /login)
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
      console.error(" Virhe kirjautumisessa:", error.message);
      res.status(500).json({ success: false, error: error.message });
  }
});

// Hae kaikki käyttäjät (vain kirjautuneille käyttäjille)
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, name, email, created_at FROM public."users"');
    res.json(result.rows);
  } catch (error) {
    console.error(" Virhe haettaessa käyttäjiä:", error.message);
    res.status(500).json({ error: error.message });
  }
});

// Hae kirjautunut käyttäjä (/me-reitti)
app.get("/me", authenticateToken, async (req, res) => {
  try {
      const userId = req.user.id;
      const result = await pool.query("SELECT id, name, email FROM users WHERE id = $1", [userId]);

      if (result.rows.length === 0) {
          return res.status(404).json({ error: "Käyttäjää ei löydy." });
      }

      res.json(result.rows[0]);
  } catch (error) {
      console.error("Virhe haettaessa käyttäjätietoja:", error);
      res.status(500).json({ error: "Käyttäjätietojen hakeminen epäonnistui." });
  }
});

// Lisää uusi käyttäjä (validoinnilla)
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
    console.error(" Virhe lisättäessä käyttäjää:", error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// Lisää käyttäjän tulot ja menot
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

      // Lasketaan menojen kokonaismäärä
      const actual_expenses = Object.values(expenses)
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
              income !== undefined && income !== "" ? parseFloat(income) : null, // NULL, jos tyhjä
              actualIncome !== undefined && actualIncome !== "" ? parseFloat(actualIncome) : null, // NULL, jos tyhjä
              actual_expenses !== undefined && actual_expenses !== "" ? parseFloat(actual_expenses) : null, // NULL, jos tyhjä
              0, // Toteutuneet menot oletuksena 0
              new Date(), 
              new Date()
          ]
        );

        res.status(201).json({ success: true, budget: result.rows[0] });

  } catch (error) {
      console.error(" Virhe tallennettaessa budjettia:", error.message);
      res.status(500).json({ error: 'Tietokantavirhe' });
  }
});

// Lisätään uusi tapahtuma tietokantaan
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
      console.error(" Virhe lisättäessä tapahtumaa:", error.message);
      res.status(500).json({ error: "Tietokantavirhe" });
  }
});

// Päivitä käyttäjän tiedot (validoinnilla)
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

// Päivitetään käyttäjän budjetin tiedot (tulot ja menot)
app.put('/api/budgets/:id', authenticateToken, async (req, res) => {
  console.log("Received PUT request for budget ID:", req.params.id);

  try {
    const { id } = req.params;
    const userId = req.user.id;
    const { toteutunut_tulot, suunniteltu_menot, toteutunut_menot } = req.body;

    // Tarkistetaan, kuuluuko budjetti käyttäjälle
    const checkBudget = await pool.query(
      `SELECT id FROM budgets WHERE id = $1 AND user_id = $2`,
      [id, userId]
    );

    if (checkBudget.rows.length === 0) {
      return res.status(404).json({ error: "Budjettia ei löytynyt tai ei oikeuksia" });
    }

    // Asetetaan NULL-arvoille oletusarvot
    const validPlannedExpenses = suunniteltu_menot !== null ? suunniteltu_menot : 0;
    const validActualExpenses = toteutunut_menot !== null ? toteutunut_menot : 0;

    // Päivitetään budjetin tiedot
    const updateBudget = await pool.query(
      `UPDATE budgets 
       SET toteutunut_tulot = $1, suunniteltu_menot = $2, toteutunut_menot = $3
       WHERE id = $4 AND user_id = $5
       RETURNING *`,
       [toteutunut_tulot, validPlannedExpenses, validActualExpenses, id, userId]
    );

    res.json({ message: "Budjetti päivitetty onnistuneesti", budget: updateBudget.rows[0] });

  } catch (error) {
    console.error("Virhe budjetin päivittämisessä:", error.message);
    res.status(500).json({ error: "Palvelinvirhe budjetin päivittämisessä" });
  }
});

// Poista käyttäjätili pysyvästi
app.delete("/api/users/me", authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id; // Haetaan käyttäjän ID tokenista

    // Poistetaan käyttäjän tiedot
    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [userId]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Käyttäjää ei löydy." });
    }

    res.json({ success: true, message: "Tilisi on poistettu pysyvästi." });

  } catch (error) {
    console.error("Virhe tilin poistamisessa:", error);
    res.status(500).json({ error: "Virhe tilin poistamisessa." });
  }
});

// Poista budjetti
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
      console.error(" Virhe budjetin poistamisessa:", error.message);
      res.status(500).json({ success: false, error: "Virhe budjetin poistamisessa" });
  }
});

// Haetaan kaikki budjetit (vain kirjautuneille käyttäjille)
app.get('/api/budgets', authenticateToken, async (req, res) => {
  try {
      const result = await pool.query(
          `SELECT 
              b.id, 
              b.user_id, 
              b.kuukausi AS month, 
              b.vuosi AS year, 
              b.toteutunut_tulot AS income, 
              b.suunniteltu_menot AS expenses, 
              b.toteutunut_menot AS actual_expenses,
              -- Lasketaan kaikki tapahtumat budjettiin liittyen
              COALESCE(SUM(CASE WHEN t.tyyppi = 'tulo' THEN t.summa ELSE 0 END), 0) AS transaction_income,
              COALESCE(SUM(CASE WHEN t.tyyppi = 'meno' THEN t.summa ELSE 0 END), 0) AS transaction_expenses
          FROM budgets b
          LEFT JOIN transactions t ON b.id = t.budget_id
          WHERE b.user_id = $1 
          GROUP BY b.id, b.user_id, b.kuukausi, b.vuosi, b.toteutunut_tulot, b.suunniteltu_menot, b.toteutunut_menot
          ORDER BY b.kuukausi ASC`,
          [req.user.id]
      );

      res.json(result.rows.map(budget => ({
          ...budget,
          actual_income: Number(budget.income || 0) + Number(budget.transaction_income || 0), // Lasketaan tulot yhteen
          actual_expenses: Number(budget.expenses || 0) + Number(budget.transaction_expenses || 0), // Lasketaan menot yhteen
          total: (Number(budget.income || 0) + Number(budget.transaction_income || 0)) - 
                 (Number(budget.actual_expenses || 0) + Number(budget.transaction_expenses || 0)) // Lasketaan saldo
      })));

  } catch (error) {
      console.error("Virhe budjettien hakemisessa:", error.message);
      res.status(500).json({ success: false, error: "Virhe budjettien hakemisessa" });
  }
});

app.get('/api/categories', async (req, res) => {
  try {
      const result = await pool.query('SELECT * FROM categories ORDER BY id ASC');
      res.json(result.rows);
  } catch (error) {
      console.error(" Virhe haettaessa kategorioita:", error);
      res.status(500).json({ error: "Tietokantavirhe" });
  }
});

// Haetaan budjettiin liittyvät tapahtumat budjetin ID:n perusteella
app.get("/api/transactions/:budgetId", async (req, res) => {
  const { budgetId } = req.params;
  
  try {
    const transactions = await pool.query(
      "SELECT * FROM transactions WHERE budget_id = $1",
      [budgetId]
    );
    res.json(transactions.rows);
  } catch (error) {
    console.error(" Virhe haettaessa tapahtumia:", error);
    res.status(500).json({ error: "Virhe haettaessa tapahtumia" });
  }
});

// Päivitä käyttäjän nimi tai salasana
app.patch("/api/users/me", authenticateToken, async (req, res) => {
  console.log("PATCH /api/users/me kutsuttu");
  try {
    const userId = req.user.id; // Haetaan käyttäjän ID tokenista
    const { newUsername, newPassword } = req.body;

    if (!newUsername && !newPassword) {
      return res.status(400).json({ error: "Anna uusi käyttäjänimi tai salasana." });
    }

    let updateFields = [];
    let values = [];
    let index = 1;

    if (newUsername) {
      updateFields.push(`name = $${index}`);
      values.push(newUsername);
      index++;
    }

    if (newPassword) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updateFields.push(`password = $${index}`);
      values.push(hashedPassword);
      index++;
    }

    values.push(userId);
    const query = `UPDATE users SET ${updateFields.join(", ")} WHERE id = $${index} RETURNING name`;
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Käyttäjää ei löydy." });
    }

    res.json({ success: true, username: result.rows[0].name });

  } catch (error) {
    console.error("Virhe päivitettäessä käyttäjätietoja:", error);
    res.status(500).json({ error: "Virhe päivitettäessä käyttäjätietoja." });
  }
});

// Haetaan yksittäinen budjetti ID:llä
app.get('/api/budgets/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id; 

    console.log("🔍 Haetaan budjetti ID:", id, "käyttäjälle", userId); 

    // Haetaan budjetin perustiedot
    const budgetResult = await pool.query(
      `SELECT id, user_id, kuukausi AS month, vuosi AS year, 
              suunniteltu_tulot AS income, toteutunut_tulot AS actual_income, 
              suunniteltu_menot AS planned_expenses, 
              toteutunut_menot AS actual_expenses, 
              suunniteltu_menot AS expenses
      FROM budgets 
      WHERE id = $1 AND user_id = $2`, 
      [id, userId]
    );

    if (budgetResult.rows.length === 0) {
      return res.status(404).json({ error: "Budjettia ei löytynyt tai sinulla ei ole oikeuksia nähdä sitä" });
    }

    const budget = budgetResult.rows[0];

    // Haetaan meno-tapahtumien yhteissumma budjetille
    const transactionExpensesResult = await pool.query(
      `SELECT COALESCE(SUM(summa), 0) AS transaction_expenses
       FROM transactions WHERE budget_id = $1 AND tyyppi = 'meno'`,
      [id]
    );

    const transaction_expenses = transactionExpensesResult.rows[0].transaction_expenses || 0;

    // Haetaan tulo-tapahtumien yhteissumma budjetille
    const transactionIncomeResult = await pool.query(
      `SELECT COALESCE(SUM(summa), 0) AS transaction_income
       FROM transactions WHERE budget_id = $1 AND tyyppi = 'tulo'`,
      [id]
    );

    const transaction_income = transactionIncomeResult.rows[0].transaction_income || 0;

    console.log("Lasketut meno-tapahtumat:", transaction_expenses);
    console.log("Lasketut tulo-tapahtumat:", transaction_income);

    // Lasketaan tapahtumat
    const actual_expenses =
      Number(budget.expenses || 0) +
      Number(transaction_expenses || 0);

    const actual_income =
      Number(budget.actual_income || 0) +
      Number(transaction_income || 0);

    console.log("Lopulliset toteutuneet menot:", actual_expenses);
    console.log("Lopulliset toteutuneet tulot:", actual_income);

    res.json({
      ...budget,
      transaction_expenses,
      transaction_income,
      actual_expenses,
      actual_income
    });

  } catch (error) {
    console.error(" Virhe haettaessa budjettia:", error.message);
    res.status(500).json({ error: "Virhe budjetin hakemisessa" });
  }
});

// Aseta palvelimen portti
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
