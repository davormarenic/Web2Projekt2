import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool(
  process.env.DATABASE_URL
    ? {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
      }
    : {
        user: process.env.DB_USER,
        host: process.env.DB_HOST,
        database: process.env.DB_NAME,
        password: process.env.DB_PASSWORD,
        port: Number(process.env.DB_PORT) || 5432,
        ssl: { rejectUnauthorized: false },
      }
);

export interface UserRecord {
  id: number;
  username: string;
  password: string;
  role: 'admin' | 'user';
  email: string;
  secret_note: string;
}

export interface CommentRecord {
  id: number;
  author: string;
  content: string;
  created_at: Date;
}

export interface VulnSettings {
  xss: boolean;
  bac: boolean;
}

export async function initDb(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS p2_users (
      id INT PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(100) NOT NULL,
      role VARCHAR(20) NOT NULL,
      email VARCHAR(100) NOT NULL,
      secret_note TEXT NOT NULL
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS p2_comments (
      id SERIAL PRIMARY KEY,
      author VARCHAR(50) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS p2_vuln_settings (
      vuln_key VARCHAR(20) PRIMARY KEY,
      enabled BOOLEAN NOT NULL DEFAULT TRUE
    );
  `);

  // Početni testni korisnici (id=1 admin, id=2 pero, id=3 ana)
  await pool.query(`
    INSERT INTO p2_users (id, username, password, role, email, secret_note)
    VALUES
      (1, 'admin', 'admin123', 'admin', 'admin@web2.fer.hr', 'TAJNA-ADMIN: Glavni API ključ sustava = FER-ADMIN-9988-SECRET'),
      (2, 'pero', 'pero123', 'user', 'pero@web2.fer.hr', 'TAJNA-PERO: OIB 12345678901, IBAN HR1223600001100000001'),
      (3, 'ana', 'ana123', 'user', 'ana@web2.fer.hr', 'TAJNA-ANA: OIB 98765432109, privatni PIN kartice = 4829')
    ON CONFLICT (id) DO NOTHING;
  `);

  // Početno stanje prekidača ranjivosti (obje uključene po zadanom)
  await pool.query(`
    INSERT INTO p2_vuln_settings (vuln_key, enabled)
    VALUES
      ('xss', TRUE),
      ('bac', TRUE)
    ON CONFLICT (vuln_key) DO NOTHING;
  `);

  // Početni pozdravni komentar ako je tablica prazna
  const countRes = await pool.query('SELECT COUNT(*)::int AS cnt FROM p2_comments');
  if (countRes.rows[0].cnt === 0) {
    await pool.query(
      'INSERT INTO p2_comments (author, content) VALUES ($1, $2)',
      ['admin', 'Dobrodošli na oglasnu ploču! Ovdje možete testirati Pohranjeni XSS.']
    );
  }
}

export async function getVulnSettings(): Promise<VulnSettings> {
  const res = await pool.query('SELECT vuln_key, enabled FROM p2_vuln_settings');
  const settings: VulnSettings = { xss: true, bac: true };
  for (const row of res.rows) {
    if (row.vuln_key === 'xss') settings.xss = Boolean(row.enabled);
    if (row.vuln_key === 'bac') settings.bac = Boolean(row.enabled);
  }
  return settings;
}

export async function setVulnSetting(key: 'xss' | 'bac', enabled: boolean): Promise<void> {
  await pool.query(
    'UPDATE p2_vuln_settings SET enabled = $1 WHERE vuln_key = $2',
    [enabled, key]
  );
}

export async function findUserByCredentials(
  username: string,
  password: string
): Promise<UserRecord | null> {
  const res = await pool.query<UserRecord>(
    'SELECT id, username, password, role, email, secret_note FROM p2_users WHERE username = $1 AND password = $2',
    [username, password]
  );
  return res.rows[0] ?? null;
}

export async function findUserById(id: number): Promise<UserRecord | null> {
  const res = await pool.query<UserRecord>(
    'SELECT id, username, password, role, email, secret_note FROM p2_users WHERE id = $1',
    [id]
  );
  return res.rows[0] ?? null;
}

export async function getAllUsers(): Promise<UserRecord[]> {
  const res = await pool.query<UserRecord>(
    'SELECT id, username, password, role, email, secret_note FROM p2_users ORDER BY id ASC'
  );
  return res.rows;
}

export async function getAllComments(): Promise<CommentRecord[]> {
  const res = await pool.query<CommentRecord>(
    'SELECT id, author, content, created_at FROM p2_comments ORDER BY id ASC'
  );
  return res.rows;
}

export async function addComment(author: string, content: string): Promise<void> {
  await pool.query(
    'INSERT INTO p2_comments (author, content) VALUES ($1, $2)',
    [author, content]
  );
}

export async function deleteComment(id: number): Promise<void> {
  await pool.query('DELETE FROM p2_comments WHERE id = $1', [id]);
}