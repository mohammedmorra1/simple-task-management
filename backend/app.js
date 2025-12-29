import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";

//connect to database
const db = new sqlite3.Database("taskManDB.db", (err) => {
  if (err) {
    console.log(err.message);
  }
  console.log("Connected to the database!");
});

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  db.all("SELECT * FROM users", (err, rows) => {
    if (err) {
      console.log(err.message);
    }
    res.json(rows);
  });
});

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  // validate inputs
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Username, email, and password are required" });
  }

  try {
    // check if the user already exists
    db.get(
      "SELECT name, email FROM users WHERE name = ? OR email = ?",
      [name, email],
      async (err, existingUser) => {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: "Database error" });
        }

        if (existingUser) {
          if (existingUser.name === name) {
            return res.status(409).json({ error: "Username already exists" });
          }
          if (existingUser.email === email) {
            return res.status(409).json({ error: "Email already exists" });
          }
        }

        // Hash the password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new user
        db.run(
          "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
          [name, email, hashedPassword],
          (err) => {
            if (err) {
              console.error(err.message);
              return res.status(500).json({ error: "Failed to create user" });
            }

            res.status(201).json({
              message: "User created successfully",
              userId: this.id,
            });
          }
        );
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // validate inputs
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    // Search for user by email
    db.get(
      "SELECT id, email, password_hash FROM users WHERE email = ?",
      [email],
      async (err, user) => {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: "Database error" });
        }

        if (!user) {
          return res.status(401).json({ message: "wrong credentials" });
        }

        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (isMatch) {
          return res.status(200).json({
            message: "successful",
            id: user.id,
          });
        } else {
          return res.status(401).json({ message: "wrong credentials" });
        }
      }
    );
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
