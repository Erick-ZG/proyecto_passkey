// Node 20+, "type": "module" en package.json
import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';

// --- ESM __dirname ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Config
const PORT = process.env.PORT || 8000;
const rpID = process.env.RPID || 'localhost';
const ORIGINS = (process.env.ORIGINS || 'http://localhost:3000,http://localhost:5173')
  .split(',')
  .map(s => s.trim());

// CORS (en prod no es necesario si todo es mismo dominio)
app.use(
  cors({
    origin: ORIGINS,
    credentials: false,
  }),
);

// --- DB en memoria ---
const db = {
  users: new Map(),
  regOptions: new Map(),
  authOptions: new Map(),
};

// Util
function getOrCreateUser(username) {
  let user = db.users.get(username);
  if (!user) {
    user = { username, passkeys: [] };
    db.users.set(username, user);
    console.log('👤 Usuario creado:', user);
  }
  return user;
}

// ---------- Registro: Opciones ----------
app.post('/register/options', async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Falta username' });

  const user = getOrCreateUser(username);

  const excludeCredentials = user.passkeys.map(pk => ({
    id: pk.id,
    transports: pk.transports,
  }));

  const options = await generateRegistrationOptions({
    rpName: 'Demo Passkeys',
    rpID,
    userName: username,
    userDisplayName: username,
    userID: isoUint8Array.fromUTF8String(username),
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    excludeCredentials,
  });

  db.regOptions.set(username, options);
  return res.json(options);
});

// ---------- Registro: Verificación ----------
app.post('/register/verify', async (req, res) => {
  const { username, credential } = req.body || {};
  if (!username || !credential) return res.status(400).json({ error: 'Faltan datos' });

  const user = db.users.get(username);
  if (!user) return res.status(400).json({ error: 'Usuario no existe' });

  const opts = db.regOptions.get(username);
  if (!opts) return res.status(400).json({ error: 'No hay options de registro activas' });

  try {
    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: opts.challenge,
      expectedOrigin: ORIGINS, // puede ser array
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential: cred, credentialDeviceType, credentialBackedUp } =
        verification.registrationInfo;

      const newPasskey = {
        id: cred.id,
        publicKey: cred.publicKey,
        counter: cred.counter,
        transports: cred.transports,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
      };

      user.passkeys.push(newPasskey);
      console.log(`✅ Passkey registrada para "${username}"`);
    }

    return res.json({ verified: verification.verified });
  } catch (err) {
    console.error('❌ Error en verificación:', err);
    return res.status(400).json({ error: err.message });
  } finally {
    db.regOptions.delete(username);
  }
});

// ---------- Debug ----------
app.get('/debug/users', (_req, res) => {
  res.json(Array.from(db.users.values()));
});

// ---------- Login: Opciones ----------
app.post('/login/options', async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Falta username' });

  const user = db.users.get(username);
  if (!user) return res.status(400).json({ error: 'Usuario no existe' });
  if (!user.passkeys.length) return res.status(400).json({ error: 'Usuario sin passkeys' });

  const allowCredentials = user.passkeys.map(pk => ({
    id: pk.id,
    transports: pk.transports,
  }));

  try {
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'preferred',
      allowCredentials,
    });

    db.authOptions.set(username, options);
    return res.json(options);
  } catch (err) {
    console.error('❌ Error generando opciones de login:', err);
    return res.status(400).json({ error: err.message });
  }
});

// ---------- Login: Verificación ----------
app.post('/login/verify', async (req, res) => {
  const { username, credential } = req.body || {};
  if (!username || !credential) return res.status(400).json({ error: 'Faltan datos' });

  const user = db.users.get(username);
  if (!user) return res.status(400).json({ error: 'Usuario no existe' });

  const opts = db.authOptions.get(username);
  if (!opts) return res.status(400).json({ error: 'No hay options de login activas' });

  try {
    const passkey = user.passkeys.find(pk => pk.id === credential.id);
    if (!passkey) return res.status(400).json({ error: 'Credencial no encontrada' });

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: opts.challenge,
      expectedOrigin: ORIGINS,
      expectedRPID: rpID,
      credential: {
        id: passkey.id,
        publicKey: passkey.publicKey,
        counter: passkey.counter,
        transports: passkey.transports,
      },
    });

    if (verification.verified && verification.authenticationInfo) {
      const { newCounter } = verification.authenticationInfo;
      passkey.counter = newCounter;
    }

    return res.json({ verified: verification.verified });
  } catch (err) {
    console.error('❌ Error en verificación login:', err);
    return res.status(400).json({ error: err.message });
  } finally {
    db.authOptions.delete(username);
  }
});

// --- Healthcheck opcional (útil en Render) ---
app.get('/healthz', (_req, res) => res.send('ok'));

// -------------- Servir FRONTEND (CRA => build) --------------
// ⚠️ Asegúrate de haber construido el frontend: `cd frontend && npm run build`
const clientBuildPath = path.join(__dirname, '../frontend/build');
app.use(express.static(clientBuildPath));

// Express 5: usa RegExp para el catch-all y evita capturar endpoints de API
app.get(/^(?!\/(register|login|debug|healthz)(\/|$)).*/, (_req, res) => {
  res.sendFile(path.join(clientBuildPath, 'index.html'));
});

// Start
app.listen(PORT, () => {
  console.log(`✅ Backend corriendo en puerto ${PORT}`);
});
