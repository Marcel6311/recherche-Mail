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
  'https://www.googleapis.com/auth/gmail.modify',
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

// FRONTEND_URL peut contenir un chemin (ex: https://x.github.io/Recherche-Mail).
// Le header Origin envoye par le navigateur, lui, ne contient jamais de chemin
// (juste https://x.github.io) — on doit donc comparer uniquement cette partie.
const FRONTEND_ORIGIN = FRONTEND_URL ? new URL(FRONTEND_URL).origin : '*';

const app = express();
app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Recherche-Mail backend en ligne.' + (USE_REDIS ? '' : ' (stockage local, non persistant)'));
});

app.get('/auth/start', (req, res) => {
  const client = newOAuthClient();
  const url = client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES,
  });
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) {
    return res.redirect(`${FRONTEND_URL}?auth_error=${encodeURIComponent(error)}`);
  }
  try {
    const client = newOAuthClient();
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    const oauth2 = google.oauth2({ auth: client, version: 'v2' });
    const { data } = await oauth2.userinfo.get();
    const email = data.email;

    if (!tokens.refresh_token) {
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

// ---------- Lecture complete d'un message ----------

function decodeBase64Url(data) {
  return Buffer.from(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function extractBodyAndAttachments(payload) {
  let plain = null;
  let html = null;
  const attachments = [];

  function walk(part) {
    if (!part) return;
    if (part.filename && part.body && part.body.attachmentId) {
      attachments.push({
        filename: part.filename,
        attachmentId: part.body.attachmentId,
        mimeType: part.mimeType || 'application/octet-stream',
        size: part.body.size || 0,
      });
    } else if (part.mimeType === 'text/plain' && part.body && part.body.data && plain === null) {
      plain = decodeBase64Url(part.body.data).toString('utf8');
    } else if (part.mimeType === 'text/html' && part.body && part.body.data && html === null) {
      html = decodeBase64Url(part.body.data).toString('utf8');
    }
    (part.parts || []).forEach(walk);
  }
  walk(payload);
  return { plain, html, attachments };
}

// Conversion HTML -> texte lisible, sans dependance externe
function htmlToText(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|tr|li|h[1-6]|table)>/gi, '\n')
    .replace(/<li[^>]*>/gi, '• ')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

app.get('/message/:email/:id', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    const client = await getAuthedClientFor(email);
    const gmail = google.gmail({ version: 'v1', auth: client });

    const msg = await gmail.users.messages.get({
      userId: 'me',
      id: req.params.id,
      format: 'full',
    });

    const headers = msg.data.payload.headers || [];
    const { plain, html, attachments } = extractBodyAndAttachments(msg.data.payload);

    let bodyText = '';
    if (plain) bodyText = plain.trim();
    else if (html) bodyText = htmlToText(html);
    else bodyText = msg.data.snippet || '';

    res.json({
      account: email,
      id: msg.data.id,
      from: extractHeader(headers, 'From'),
      to: extractHeader(headers, 'To'),
      cc: extractHeader(headers, 'Cc'),
      date: extractHeader(headers, 'Date'),
      subject: extractHeader(headers, 'Subject'),
      body: bodyText,
      attachments,
    });
  } catch (err) {
    console.error('Erreur lecture message', err.message);
    const status = err.message && (err.message.includes('invalid_grant') || err.message.includes('invalid_token')) ? 401 : 500;
    res.status(status).json({ error: err.message });
  }
});

app.get('/attachment/:email/:messageId/:attachmentId', async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email);
    const client = await getAuthedClientFor(email);
    const gmail = google.gmail({ version: 'v1', auth: client });

    const att = await gmail.users.messages.attachments.get({
      userId: 'me',
      messageId: req.params.messageId,
      id: req.params.attachmentId,
    });

    const buffer = decodeBase64Url(att.data.data);
    const filename = (req.query.filename || 'piece-jointe').replace(/[\r\n"]/g, '');
    const mime = req.query.mime || 'application/octet-stream';

    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
    res.send(buffer);
  } catch (err) {
    console.error('Erreur piece jointe', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Mise a la corbeille (reversible 30 jours dans Gmail) ----------
// Recoit { items: [ { account, ids: [...] }, ... ] } et met tous les
// messages listes a la corbeille du compte correspondant.

app.post('/trash', async (req, res) => {
  try {
    const items = req.body && req.body.items;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'items manquants' });
    }

    const outcomes = await Promise.all(items.map(async ({ account, ids }) => {
      try {
        if (!Array.isArray(ids) || ids.length === 0) return { account, ok: true, trashed: 0 };
        const client = await getAuthedClientFor(account);
        const gmail = google.gmail({ version: 'v1', auth: client });
        await gmail.users.messages.batchModify({
          userId: 'me',
          requestBody: { ids, addLabelIds: ['TRASH'], removeLabelIds: ['INBOX'] },
        });
        return { account, ok: true, trashed: ids.length };
      } catch (err) {
        console.error(`Erreur corbeille pour ${account}`, err.message);
        const needsReconnect = err.message && (
          err.message.includes('insufficient') ||
          err.message.includes('Insufficient') ||
          err.message.includes('invalid_grant') ||
          err.message.includes('invalid_token')
        );
        return { account, ok: false, needsReconnect, error: err.message, trashed: 0 };
      }
    }));

    res.json({ outcomes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Recherche-Mail backend demarre sur le port ${PORT} (stockage: ${USE_REDIS ? 'Upstash Redis' : 'fichier local'})`);
});
