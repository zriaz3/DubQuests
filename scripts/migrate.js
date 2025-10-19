import fs from 'fs';
import path from 'path';
import 'dotenv/config';
import pg from 'pg';
const { Pool } = pg;

// Read the schema.sql file
const sql = fs.readFileSync(path.resolve('schema.sql'), 'utf8');

// Connect to the database using .env
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const run = async () => {
  const client = await pool.connect();
  try {
    await client.query(sql);
    console.log('✅ Migration applied');
  } catch (err) {
    console.error('❌ Migration failed:', err);
  } finally {
    client.release();
    process.exit();
  }
};

run();
