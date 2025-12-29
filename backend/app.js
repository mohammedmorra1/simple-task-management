import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import bcrypt from "bcryptjs";

//connect to database
const db = new sqlite3.Database("database.db", (err) => {
  if (err) {
    console.log(err.message);
  }
  console.log("Connected to the database!");
});
