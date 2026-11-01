const express = require('express');
const { Pool } = require('pg');
const QRCode = require('qrcode');
const { randomUUID } = require('node:crypto');
const { auth, requiresAuth } = require('express-openid-connect');
const { auth: jwt, requiredScopes } = require('express-oauth2-jwt-bearer');

const base = process.env.AUTH0_BASE_URL;
const db = new Pool({ connectionString: process.env.POSTGRES_URL?.split('?')[0], ssl: { rejectUnauthorized: false } });
const ready = db.query(`CREATE TABLE IF NOT EXISTS passes (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  document TEXT NOT NULL,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'ACTIVE'
)`);

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);

async function findPass(id) {
  if (!UUID.test(id)) return null;
  const { rows } = await db.query('SELECT * FROM passes WHERE id = $1', [id]);
  if (!rows[0]) return null;
  const p = rows[0];
  return { id: p.id, name: p.name, document: p.document, issuedAt: p.issued_at.toISOString().replace(/\.\d+Z$/, 'Z'), status: p.status };
}

const app = express();
app.set('trust proxy', 1);
app.use(async (req, res, next) => { await ready; next(); });
app.use(auth({
  authRequired: false,
  auth0Logout: true,
  baseURL: base,
  secret: process.env.AUTH0_SECRET,
  clientID: process.env.AUTH0_CLIENT_ID,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  authorizationParams: { response_type: 'code' },
}));

app.get('/', async (req, res) => {
  const { rows } = await db.query(
    "SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE status = 'ACTIVE') AS active FROM passes");
  let html = `<p>Ukupno propusnica: ${rows[0].total}</p><p>Aktivnih propusnica: ${rows[0].active}</p>`;
  if (!req.oidc.isAuthenticated()) return res.send(html + '<a href="/login">Prijava</a>');

  const passes = await db.query('SELECT * FROM passes ORDER BY issued_at DESC');
  html += '<a href="/logout">Odjava</a><table>';
  for (const p of passes.rows) {
    html += `<tr><td><a href="/info/${p.id}">${esc(p.name)}</a></td><td>${esc(p.document)}</td>
      <td>${p.issued_at.toISOString()}</td><td>${p.status}</td>
      <td><form method="post" action="/cancel/${p.id}"><button>Poništi</button></form></td>
      <td><form method="post" action="/delete/${p.id}"><button>Obriši</button></form></td></tr>`;
  }
  res.send(html + '</table>');
});

app.get('/info/:id', async (req, res) => {
  const p = await findPass(req.params.id);
  if (!p) return res.status(404).send('Propusnica ne postoji');
  res.send(`<p>Status: ${p.status}</p><p>Ime i prezime: ${esc(p.name)}</p>
    <p>Dokument: ${esc(p.document)}</p><p>Izdano: ${p.issuedAt}</p>`);
});

app.post('/cancel/:id', requiresAuth(), async (req, res) => {
  if (UUID.test(req.params.id)) await db.query("UPDATE passes SET status = 'CANCELLED' WHERE id = $1", [req.params.id]);
  res.redirect('/');
});

app.post('/delete/:id', requiresAuth(), async (req, res) => {
  if (UUID.test(req.params.id)) await db.query('DELETE FROM passes WHERE id = $1', [req.params.id]);
  res.redirect('/');
});

const checkJwt = jwt({ audience: process.env.AUTH0_AUDIENCE, issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL });

app.get('/passes/:id', checkJwt, requiredScopes('read:passes'), async (req, res) => {
  const p = await findPass(req.params.id);
  if (!p) return res.sendStatus(404);
  res.json(p);
});

app.post('/passes', checkJwt, requiredScopes('create:passes'), express.json(), async (req, res) => {
  const { name, document } = req.body ?? {};
  if (typeof name !== 'string' || typeof document !== 'string' || !name.trim() || !document.trim()) {
    return res.sendStatus(400);
  }
  const id = randomUUID();
  await db.query('INSERT INTO passes (id, name, document) VALUES ($1, $2, $3)', [id, name.trim(), document.trim()]);
  const png = await QRCode.toBuffer(`${base}/info/${id}`);
  res.status(201).location(`${base}/passes/${id}`).type('png').send(png);
});

if (require.main === module) app.listen(process.env.PORT || 3000);

module.exports = app;
