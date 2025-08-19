// Node 20+, "type": "module" en package.json
import express from 'express';
import cors from 'cors';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';

const app = express();
app.use(express.json());

// Config
const rpID = process.env.RPID || 'localhost';
const ORIGINS = (process.env.ORIGINS || 'http://localhost:3000,http://localhost:5173')
  .split(',')
  .map(s => s.trim());

// CORS (para front en 3000 y/o 5173)
app.use(
  cors({
    origin: ORIGINS,
    credentials: false,
  }),
);

// DB en memoria
// user = { username, userID (Base64URLString o ignorado), passkeys: WebAuthnCredential[] }
const db = {
  users: new Map(),              // key: username => value: { username, passkeys: [] }
  regOptions: new Map(),         // key: username => last registration options
  authOptions: new Map(),        // key: username => last auth options
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

  // Excluir credenciales ya registradas para este usuario
  const excludeCredentials = user.passkeys.map(pk => ({
    id: pk.id,           // Base64URLString (v11+)
    transports: pk.transports, // opcional
  }));

  // Si quieres forzar tu propio userID (BufferSource), usa isoUint8Array
  // Puedes omitir userID y dejar que SWA genere uno aleatorio válido.
  const options = await generateRegistrationOptions({
    rpName: 'Demo Passkeys',
    rpID,
    userName: username,
    userDisplayName: username,
    userID: isoUint8Array.fromUTF8String(username), // ✅ Uint8Array (cumple v10+)
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    excludeCredentials,
  });

  db.regOptions.set(username, options);
  return res.json(options); // ⚠️ devolver tal cual, sin transformar
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
      response: credential,                 // objeto enviado desde el navegador
      expectedChallenge: opts.challenge,    // v13 usa .challenge directo
      expectedOrigin: ORIGINS,              // puede ser un array de origins válidos
      expectedRPID: rpID,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credential: cred, credentialDeviceType, credentialBackedUp } =
        verification.registrationInfo;

      const newPasskey = {
        id: cred.id,                         // Base64URL string
        publicKey: cred.publicKey,           // Uint8Array
        counter: cred.counter,
        transports: cred.transports,         // string[]
        deviceType: credentialDeviceType,    // opcional
        backedUp: credentialBackedUp,        // opcional
      };

      user.passkeys.push(newPasskey);

      console.log(`✅ Passkey registrada para usuario "${username}":`, newPasskey);
      console.log(`📌 Estado actual del usuario:`, user);
    }

    return res.json({ verified: verification.verified });
  } catch (err) {
    console.error('❌ Error en verificación:', err);
    return res.status(400).json({ error: err.message });
  } finally {
    db.regOptions.delete(username);
  }
});

// ---------- Debug: ver todos los usuarios ----------
app.get('/debug/users', (req, res) => {
  const allUsers = Array.from(db.users.values());
  res.json(allUsers);
});

// ---------- Login: Opciones ----------
app.post('/login/options', async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Falta username' });

  const user = db.users.get(username);
  if (!user) return res.status(400).json({ error: 'Usuario no existe' });
  if (!user.passkeys.length) return res.status(400).json({ error: 'Usuario sin passkeys' });

  // allowedCredentials: ids en Base64URL (no Buffers, no undefined)
  const allowCredentials = user.passkeys.map(pk => ({
    id: pk.id,             // Base64URLString
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
    // Busca la passkey por el id que envía el browser (Base64URL)
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
      passkey.counter = newCounter; // actualiza counter
    }

    return res.json({ verified: verification.verified });
  } catch (err) {
    console.error('❌ Error en verificación login:', err);
    return res.status(400).json({ error: err.message });
  } finally {
    db.authOptions.delete(username);
  }
});

app.listen(8000, () => {
  console.log('✅ Backend corriendo en http://localhost:8000');
});
