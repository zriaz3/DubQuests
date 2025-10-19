// server.js
import 'dotenv/config';
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v4 as uuid } from 'uuid';
import pkg from 'pg';
import { z } from 'zod';

import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';

const app = express();

/* ---------- Static (serve your /public when running locally) ---------- */
app.use(express.static('public'));

/* ---------- Middleware ---------- */
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  'https://dubquests.netlify.app' // your Netlify site
];

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error('Not allowed by CORS'));
    }
  })
);
app.use(express.json());
app.use(morgan('dev'));

/* ---------- Database ---------- */
const { Pool } = pkg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/* ---------- AWS S3 ---------- */
const s3 = new S3Client({
  region: process.env.S3_REGION || 'ca-central-1',
  endpoint: process.env.S3_ENDPOINT || undefined,
  forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'true',
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY
  }
});
const BUCKET = process.env.S3_BUCKET;
const SIGNED_TTL = parseInt(process.env.SIGNED_URL_TTL_SECONDS || '60', 10);

/* ---------- Auth helpers ---------- */
function signToken(user) {
  return jwt.sign(
    { uid: user.id, email: user.email }, // payload kept small on purpose
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES || '7d' }
  );
}

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* ---------- Validation Schemas ---------- */
// Signup now collects name + username + email + password
const RegisterSchema = z.object({
  name: z.string().trim().min(1, 'Name required').max(120),
  username: z
    .string()
    .trim()
    .min(3, 'Username too short')
    .max(30, 'Username too long')
    .regex(/^[a-z0-9_]+$/i, 'Letters, numbers, underscore only'),
  email: z.string().email(),
  password: z.string().min(8)
});

// Login accepts either a username OR an email in one field
const LoginSchema = z.object({
  identifier: z.string().trim().min(1), // username or email
  password: z.string().min(8)
});

const UploadReqSchema = z.object({
  filename: z.string().min(1),
  contentType: z.string().startsWith('image/')
});

const PhotoCreateSchema = z.object({
  key: z.string().min(1),
  mime: z.string().startsWith('image/'),
  bytes: z.number().int().positive(),
  caption: z.string().max(500).optional(),
  takenAt: z.string().datetime().optional()
});

const FriendReqSchema = z.object({ userId: z.string().uuid() });
const FriendAcceptSchema = z.object({ friendshipId: z.string().uuid() });

/* ---------- Auth Routes ---------- */
// REGISTER: creates user with name, username, email, password
app.post('/auth/register', async (req, res) => {
  const parse = RegisterSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json(parse.error.format());
  const { name, username, email, password } = parse.data;

  const hash = await bcrypt.hash(password, 12);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (name, username, email, password_hash)
       VALUES ($1,$2,$3,$4)
       RETURNING id, name, username, email`,
      [name, username, email.toLowerCase(), hash]
    );
    const token = signToken(rows[0]);
    res.json({ user: rows[0], token });
  } catch (e) {
    if (e.code === '23505') {
      // unique_violation – decide which unique hit
      const detail = (e.detail || '').toLowerCase();
      if (detail.includes('username')) {
        return res.status(409).json({ error: 'Username already taken' });
      }
      return res.status(409).json({ error: 'Email already exists' });
    }
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGIN: accepts identifier (username or email) + password
app.post('/auth/login', async (req, res) => {
  const parse = LoginSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json(parse.error.format());
  const { identifier, password } = parse.data;

  const looksEmail = identifier.includes('@');
  const { rows } = await pool.query(
    looksEmail
      ? 'SELECT * FROM users WHERE lower(email) = lower($1)'
      : 'SELECT * FROM users WHERE lower(username) = lower($1)',
    [identifier]
  );

  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signToken(user);
  res.json({ user: { id: user.id, name: user.name, username: user.username, email: user.email }, token });
});

/* ---------- Session restore ---------- */
app.get('/me', auth, async (req, res) => {
  const { rows } = await pool.query(
    'SELECT id, name, username, email, created_at FROM users WHERE id = $1',
    [req.user.uid]
  );
  if (!rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json({ user: rows[0] });
});

/* ---------- Friendships ---------- */
app.post('/friends/request', auth, async (req, res) => {
  const parse = FriendReqSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json(parse.error.format());
  const { userId } = parse.data;

  if (userId === req.user.uid) return res.status(400).json({ error: 'Cannot friend yourself' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO friendships (requester, addressee)
       VALUES ($1,$2)
       ON CONFLICT (least(requester, addressee), greatest(requester, addressee)) DO NOTHING
       RETURNING *`,
      [req.user.uid, userId]
    );
    if (!rows[0]) return res.status(200).json({ info: 'Already requested or exists' });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/friends/accept', auth, async (req, res) => {
  const parse = FriendAcceptSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json(parse.error.format());
  const { friendshipId } = parse.data;

  const { rows } = await pool.query('SELECT * FROM friendships WHERE id=$1', [friendshipId]);
  const f = rows[0];
  if (!f) return res.status(404).json({ error: 'Not found' });
  if (f.addressee !== req.user.uid && f.requester !== req.user.uid)
    return res.status(403).json({ error: 'Not authorized' });

  const { rows: upd } = await pool.query(
    `UPDATE friendships SET status='accepted', accepted_at=now() WHERE id=$1 RETURNING *`,
    [friendshipId]
  );
  res.json(upd[0]);
});

/* ---------- Photo Upload Flow ---------- */
app.post('/photos/upload-url', auth, async (req, res) => {
  const parse = UploadReqSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json(parse.error.format());
  const { filename, contentType } = parse.data;

  const key = `uploads/${req.user.uid}/${uuid()}-${filename}`;
  const cmd = new PutObjectCommand({
    Bucket: BUCKET,
    Key: key,
    ContentType: contentType
  });
  const url = await getSignedUrl(s3, cmd, { expiresIn: SIGNED_TTL });
  res.json({ url, key, expiresIn: SIGNED_TTL });
});

app.post('/photos', auth, async (req, res) => {
  const parse = PhotoCreateSchema.safeParse(req.body);
  if (!parse.success) return res.status(400).json(parse.error.format());
  const { key, mime, bytes, caption, takenAt } = parse.data;

  try {
    const { rows } = await pool.query(
      `INSERT INTO photos (owner, storage_key, mime, bytes, caption, taken_at)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [req.user.uid, key, mime, bytes, caption || null, takenAt || null]
    );
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- Feed ---------- */
app.get('/feed', auth, async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit || '30', 10), 100);
  const offset = Math.max(parseInt(req.query.offset || '0', 10), 0);

  const { rows } = await pool.query(
    `
    WITH my_friends AS (
      SELECT CASE
               WHEN requester = $1 THEN addressee
               ELSE requester
             END AS friend_id
      FROM friendships
      WHERE status='accepted' AND (requester=$1 OR addressee=$1)
    )
    SELECT p.*
    FROM photos p
    WHERE p.owner = $1
       OR p.owner IN (SELECT friend_id FROM my_friends)
    ORDER BY p.created_at DESC
    LIMIT $2 OFFSET $3
    `,
    [req.user.uid, limit, offset]
  );

  const out = await Promise.all(
    rows.map(async (r) => {
      const cmd = new GetObjectCommand({ Bucket: BUCKET, Key: r.storage_key });
      const signed = await getSignedUrl(s3, cmd, { expiresIn: SIGNED_TTL });
      return { ...r, signedUrl: signed, expiresIn: SIGNED_TTL };
    })
  );
  res.json(out);
});

/* ---------- Single Photo URL ---------- */
app.get('/photos/:id/url', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM photos WHERE id=$1', [req.params.id]);
  const p = rows[0];
  if (!p) return res.status(404).json({ error: 'Not found' });

  const { rows: fr } = await pool.query(
    `
    SELECT 1 FROM friendships
    WHERE status='accepted'
      AND (
        (requester=$1 AND addressee=$2)
        OR
        (requester=$2 AND addressee=$1)
      )
    LIMIT 1
    `,
    [req.user.uid, p.owner]
  );

  const allowed = p.owner === req.user.uid || fr.length > 0;
  if (!allowed) return res.status(403).json({ error: 'Not allowed' });

  const cmd = new GetObjectCommand({ Bucket: BUCKET, Key: p.storage_key });
  const signed = await getSignedUrl(s3, cmd, { expiresIn: SIGNED_TTL });
  res.json({ url: signed, expiresIn: SIGNED_TTL });
});

/* ---------- Health Check ---------- */
app.get('/healthz', (_req, res) => res.send('ok'));

/* ---------- Start Server ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`✅ Friends Photos API running on :${PORT} (S3 bucket: ${BUCKET})`)
);
