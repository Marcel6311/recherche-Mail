// Backend Recherche-Mail
// Gere le flux OAuth "authorization code" avec Google, stocke les refresh tokens
// (chiffres) et expose une recherche Gmail fusionnee sur plusieurs comptes.
//
// IMPORTANT sur le stockage : les plans gratuits des hebergeurs (Render en
// particulier) ont un disque EPHEMERE — tout fichier ecrit localement est
// perdu a chaque redemarrage/mise en veille du service. Pour eviter de
// perdre les comptes connectes en permanence, ce serveur utilise Upstash
// Redis (gratuit, sans carte bancaire) comme stockage persistant si
// UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN sont definis. A defaut,
// il retombe sur un fichier local (pratique en developpement uniquement).

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  REDIRECT_URI,
  FRONTEND_URL,
  ENCRYPTION_KEY, // 64 caracteres hex = 32 octets
  UPSTASH_REDIS_REST_URL,
  UPSTASH_REDIS_REST_TOKEN,
  PORT = 3000,
} = process.env;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !REDIRECT_URI || !ENCRYPTION_KEY) {
  console.error('Variables d\'environnement manquantes. Voir .env.example');
  process.exit(1);
}

const USE_REDIS = Boolean(UPSTASH_REDIS_REST_URL && UPSTASH_REDIS_REST_TOKEN);
if (!USE_REDIS) {
  console.warn(
    'ATTENTION: UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN absents. ' +
    'Stockage local (fichier) utilise — les comptes connectes seront PERDUS ' +
    'a chaque redemarrage du service sur un hebergeur a disque ephemere (Render free).'
  );
}

const DATA_FILE = path.join(__dirname, 'data', 'tokens.enc.json');
const REDIS_KEY = 'recherche_mail_accounts';
const SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/userinfo.email',
  'openid',
];

// ---------- Chiffrement (AES-256-GCM) ----------

function encrypt(text) {
  const iv = crypto.randomBytes(12);
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}

function decrypt(payload) {
  const raw = Buffer.from(payload, 'base64');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const key = Buffer.from(ENCRYPTION_KEY, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString('utf8');
}

// ---------- Stockage : Upstash Redis (persistant) ou fichier local (dev) ----------

async function redisCommand(command) {
  const res = await fetch(UPSTASH_REDIS_REST_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${UPSTASH_REDIS_REST_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(command),
  });
  if (!res.ok) throw new Error(`Upstash HTTP ${res.status}`);
  const data = await res.json();
  if (data.error) throw new Error(`Upstash: ${data.error}`);
  return data.result;
}

async function loadAccounts() {
  if (USE_REDIS) {
    const blob = await redisCommand(['GET', REDIS_KEY]);
    if (!blob) return {};
    return JSON.parse(decrypt(blob));
  }
  if (!fs.existsSync(DATA_FILE)) return {};
  const blob = fs.readFileSync(DATA_FILE, 'utf8');
  if (!blob.trim()) return {};
  return JSON.parse(decrypt(blob));
}

async function saveAccounts(accounts) {
  const blob = encrypt(JSON.stringify(accounts));
  if (USE_REDIS) {
    await redisCommand(['SET', REDIS_KEY, blob]);
    return;
  }
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, blob);
}

// ---------- OAuth helpers ----------

function newOAuthClient() {
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI);
}

async function getAuthedClientFor(email) {
  const accounts = await loadAccounts();
  const account = accounts[email];
  if (!account) throw new Error(`Compte inconnu: ${email}`);

  const client = newOAuthClient();
  client.setCredentials({ refresh_token: account.refresh_token });

  // googleapis rafraichit automatiquement l'access token quand il expire.
  // Google ne renvoie generalement pas de nouveau refresh_token a cette
  // occasion, mais on le persiste par securite si c'est le cas.
  client.on('tokens', (tokens) => {
    if (tokens.refresh_token) {
      loadAccounts().then((current) => {
        if (current[email]) {
          current[email].refresh_token = tokens.refresh_token;
          saveAccounts(current);
        }
      });
    }
  });

  return client;
}

// ---------- App ----------

const app = express();
app.use(cors({ origin: FRONTEND_URL || '*' }));
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Recherche-Mail backend en ligne.' + (USE_REDIS ? '' : ' (stockage local, non persistant)'));
});

// Etape 1 : lance le flux OAuth pour un compte
app.get('/auth/start', (req, res) => {
  const client = newOAuthClient();
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent', // force l'emission d'un refresh_token a chaque fois
    scope: SCOPES,
  });
  res.redirect(url);
});

// Etape 2 : callback Google, echange le code contre les tokens
app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) {
    return res.redirect(`${FRONTEND_URL}?auth_error=${encodeURIComponent(error)}`);
  }
  try {
    const client = newOAuthClient();
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    // Recupere l'email associe a ce compte
    const oauth2 = google.oauth2({ auth: client, version: 'v2' });
    const { data } = await oauth2.userinfo.get();
    const email = data.email;

    if (!tokens.refresh_token) {
      // Arrive si le compte avait deja donne son consentement sans "prompt=consent"
      return res.redirect(`${FRONTEND_URL}?auth_error=no_refresh_token`);
    }

    const accounts = await loadAccounts();
    accounts[email] = {
      refresh_token: tokens.refresh_token,
      connected_at: new Date().toISOString(),
      status: 'ok',
    };
    await saveAccounts(accounts);

    res.redirect(`${FRONTEND_URL}?connected=${encodeURIComponent(email)}`);
  } catch (err) {
    console.error('Erreur callback OAuth', err);
    res.redirect(`${FRONTEND_URL}?auth_error=exchange_failed`);
  }
});

// Liste des comptes connectes (sans exposer les tokens)
app.get('/accounts', async (req, res) => {
  try {
    const accounts = await loadAccounts();
    const list = Object.entries(accounts).map(([email, a]) => ({
      email,
      connected_at: a.connected_at,
      status: a.status || 'ok',
    }));
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deconnexion d'un compte
app.delete('/accounts/:email', async (req, res) => {
  try {
    const accounts = await loadAccounts();
    delete accounts[decodeURIComponent(req.params.email)];
    await saveAccounts(accounts);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Construit la requete Gmail (q=) a partir des parametres du constructeur
function buildQuery(params) {
  const parts = [];
  if (params.q) parts.push(params.q);
  if (params.from) parts.push(`from:${params.from}`);
  if (params.to) parts.push(`to:${params.to}`);
  if (params.subject) parts.push(`subject:${params.subject}`);
  if (params.after) parts.push(`after:${params.after}`);
  if (params.before) parts.push(`before:${params.before}`);
  if (params.hasAttachment === 'true') parts.push('has:attachment');
  if (params.label) parts.push(`label:${params.label}`);
  return parts.join(' ');
}

function extractHeader(headers, name) {
  const h = headers.find((x) => x.name.toLowerCase() === name.toLowerCase());
  return h ? h.value : '';
}

async function searchAccount(email, query, maxResults) {
  try {
    const client = await getAuthedClientFor(email);
    const gmail = google.gmail({ version: 'v1', auth: client });

    const listRes = await gmail.users.messages.list({
      userId: 'me',
      q: query,
      maxResults: maxResults || 25,
    });
    const messages = listRes.data.messages || [];

    const detailed = await Promise.all(
      messages.map(async (m) => {
        const msg = await gmail.users.messages.get({
          userId: 'me',
          id: m.id,
          format: 'metadata',
          metadataHeaders: ['From', 'To', 'Subject', 'Date'],
        });
        const headers = msg.data.payload.headers || [];
        return {
          account: email,
          id: m.id,
          threadId: m.threadId,
          snippet: msg.data.snippet,
          from: extractHeader(headers, 'From'),
          to: extractHeader(headers, 'To'),
          subject: extractHeader(headers, 'Subject'),
          date: extractHeader(headers, 'Date'),
          internalDate: Number(msg.data.internalDate || 0),
          link: `https://mail.google.com/mail/u/0/#all/${m.id}`,
        };
      })
    );

    const accounts = await loadAccounts();
    if (accounts[email]) {
      accounts[email].status = 'ok';
      await saveAccounts(accounts);
    }
    return { email, ok: true, results: detailed };
  } catch (err) {
    console.error(`Erreur recherche pour ${email}`, err.message);
    const needsReconnect = err.message && (err.message.includes('invalid_grant') || err.message.includes('invalid_token'));
    const accounts = await loadAccounts();
    if (accounts[email]) {
      accounts[email].status = needsReconnect ? 'needs_reconnect' : 'error';
      await saveAccounts(accounts);
    }
    return { email, ok: false, error: err.message, results: [] };
  }
}

// Recherche fusionnee sur tous les comptes connectes
app.get('/search', async (req, res) => {
  try {
    const accounts = await loadAccounts();
    const emails = Object.keys(accounts);
    if (emails.length === 0) {
      return res.json({ results: [], accounts: [] });
    }

    const query = buildQuery(req.query);
    const maxResults = req.query.maxResults ? Number(req.query.maxResults) : 25;

    const perAccount = await Promise.all(
      emails.map((email) => searchAccount(email, query, maxResults))
    );

    const merged = perAccount
      .flatMap((r) => r.results)
      .sort((a, b) => b.internalDate - a.internalDate);

    res.json({
      query,
      results: merged,
      accounts: perAccount.map(({ email, ok, error }) => ({ email, ok, error })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Recherche-Mail backend demarre sur le port ${PORT} (stockage: ${USE_REDIS ? 'Upstash Redis' : 'fichier local'})`);
});
