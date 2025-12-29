import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

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

// JWT Secret Key (in production, use environment variable)
const JWT_SECRET = "hakonamatata";

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (token == null) {
    return res.sendStatus(401); // Unauthorized
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403); // Forbidden
    }
    req.user = user;
    next();
  });
};

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
          // Generate JWT token
          const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: "24h" }
          );

          return res.status(200).json({
            message: "successful",
            id: user.id,
            token: token,
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

// Example protected route
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route", user: req.user });
});

// Create a new task
app.post("/create_task", authenticateToken, (req, res) => {
  const { user_id, title, description } = req.body;

  // Validate inputs
  if (!user_id || !title || !description) {
    return res.status(400).json({
      error: "user_id, title, and description are required",
    });
  }

  // Verify that the authenticated user is creating a task for themselves
  console.log(req.user.id, user_id);
  if (user_id != req.user.id) {
    return res.status(403).json({
      error: "You can only create tasks for yourself",
    });
  }

  // Insert new task with default status 'pending' and current timestamp
  db.run(
    "INSERT INTO tasks (user_id, title, description, status, created_at) VALUES (?, ?, ?, 'pending', CURRENT_TIMESTAMP)",
    [user_id, title, description],
    function (err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: "Failed to create task" });
      }

      res.status(201).json({
        message: "Task created successfully",
        taskId: this.id,
      });
    }
  );
});

// List all tasks for the authenticated user
app.get("/list_user_tasks", authenticateToken, (req, res) => {
  const { user_id } = req.query;

  // Validate input
  if (!user_id) {
    return res.status(400).json({
      error: "user_id query parameter is required",
    });
  }

  // Verify that the authenticated user is requesting their own tasks
  if (user_id != req.user.id.toString()) {
    return res.status(403).json({
      error: "You can only view your own tasks",
    });
  }

  // Retrieve all tasks for the specified user
  db.all(
    "SELECT id, title, description, status, created_at FROM tasks WHERE user_id = ? ORDER BY created_at DESC",
    [user_id],
    (err, rows) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: "Failed to retrieve tasks" });
      }

      res.status(200).json({
        message: "Tasks retrieved successfully",
        tasks: rows,
      });
    }
  );
});

// Update an existing task
app.put("/update_task", authenticateToken, (req, res) => {
  const { user_id, id, status } = req.body;

  // Validate inputs
  if (!user_id || !id || !status) {
    return res.status(400).json({
      error: "user_id, id, and status are required",
    });
  }

  // Validate status value
  const validStatuses = ["pending", "in_progress", "done"];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({
      error: "Status must be one of: pending, in_progress, or done",
    });
  }

  // Verify that the authenticated user is updating their own task
  if (user_id != req.user.id.toString()) {
    return res.status(403).json({
      error: "You can only update your own tasks",
    });
  }

  // First check if the task exists and belongs to the user
  db.get(
    "SELECT id FROM tasks WHERE id = ? AND user_id = ?",
    [id, user_id],
    (err, task) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: "Database error" });
      }

      if (!task) {
        return res.status(404).json({
          error: "Task not found or does not belong to you",
        });
      }

      // Update the task status
      let confirmationCode = 0;
      db.run(
        "UPDATE tasks SET status = ? WHERE id = ? AND user_id = ?",
        [status, id, user_id],
        function (err) {
          if (err) {
            console.error(err.message);
            return res.status(500).json({ error: "Failed to update task" });
          }

          confirmationCode = 1;
          res.status(200).json({
            message: "Task updated successfully",
            confirmationCode: confirmationCode,
            taskId: id,
            newStatus: status,
          });
        }
      );
    }
  );
});

// Delete a task
app.delete("/delete_task", authenticateToken, (req, res) => {
  const { user_id, id } = req.body;

  // Validate inputs
  if (!user_id || !id) {
    return res.status(400).json({
      error: "user_id and id are required",
    });
  }

  // Verify that the authenticated user is deleting their own task
  if (user_id != req.user.id.toString()) {
    return res.status(403).json({
      error: "You can only delete your own tasks",
    });
  }

  // First check if the task exists and belongs to the user
  db.get(
    "SELECT id FROM tasks WHERE id = ? AND user_id = ?",
    [id, user_id],
    (err, task) => {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: "Database error" });
      }

      if (!task) {
        return res.status(404).json({
          confirmationCode: 0,
          taskId: id,
          message: "Task not found or does not belong to you",
        });
      }

      // Delete the task
      db.run(
        "DELETE FROM tasks WHERE id = ? AND user_id = ?",
        [id, user_id],
        function (err) {
          if (err) {
            console.error(err.message);
            return res.status(500).json({ error: "Failed to delete task" });
          }

          res.status(200).json({
            confirmationCode: 1,
            taskId: id,
            message: "Task deleted successfully",
          });
        }
      );
    }
  );
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
