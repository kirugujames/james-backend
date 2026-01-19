import { Sequelize } from "sequelize";
import mysql from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();

const DB_NAME = process.env.DB_NAME || process.env.MYSQL_DB || "shikanac_sfu";
const DB_USER = process.env.DB_USER || process.env.MYSQL_USER || "shikanac_shikanacs";
const DB_PASS = process.env.DB_PASSWORD || process.env.MYSQL_PASSWORD;
const DB_HOST = process.env.DB_HOST || process.env.MYSQL_HOST || "sg-s2.serverpanel.com";
const DB_PORT = process.env.DB_PORT || process.env.MYSQL_PORT || 3306;

// Create the database if it doesn't exist (ONLY for local development)
async function ensureDatabase() {
  // Skip database creation on Vercel (production)
  if (process.env.VERCEL || process.env.NODE_ENV === 'production') {
    console.log('Skipping database creation in production (use cPanel to create database)');
    return;
  }

  try {
    const connection = await mysql.createConnection({
      host: DB_HOST,
      user: DB_USER,
      password: DB_PASS,
      port: DB_PORT,
      ssl: false
    });

    await connection.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;`);
    console.log(`Database "${DB_NAME}" is ready.`);
    await connection.end();
  } catch (error) {
    console.error("Error creating database:", error);
    // Don't exit in production, continue anyway
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
}

// Initialize Sequelize after ensuring the database exists
await ensureDatabase();

const sequelize = new Sequelize(DB_NAME, DB_USER, DB_PASS, {
  host: DB_HOST,
  port: DB_PORT,
  dialect: "mysql",
  dialectOptions: {
    connectTimeout: 60000,
    ssl: false  // Important: cPanel MySQL doesn't require SSL
  },
  pool: {
    max: 5,
    min: 0,
    acquire: 30000,
    idle: 10000
  },
  logging: false
});

try {
  await sequelize.authenticate();
  console.log("Connected to database successfully!");
} catch (error) {
  console.error("Database connection failed:", error);
  // Don't crash in serverless environment
  if (process.env.NODE_ENV !== 'production') {
    throw error;
  }
}

export default sequelize;