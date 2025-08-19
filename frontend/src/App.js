import { useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';

// En CRA se usan variables de entorno con prefijo REACT_APP_
// En local: REACT_APP_API_URL=http://localhost:8000
// En Render: REACT_APP_API_URL=https://tu-backend.onrender.com
const API_BASE = process.env.REACT_APP_API_URL || '';

export default function App() {
  const [username, setUsername] = useState('');
  const [msg, setMsg] = useState('');

  const postJSON = async (url, body) => {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
    return data;
  };

  const handleRegister = async () => {
    try {
      setMsg('📥 Pidiendo opciones de registro...');
      const options = await postJSON(`${API_BASE}/register/options`, { username });
      const attResp = await startRegistration({ optionsJSON: options });
      const v = await postJSON(`${API_BASE}/register/verify`, { username, credential: attResp });
      setMsg(v.verified ? '✅ Passkey registrada' : '❌ Registro no verificado');
    } catch (e) {
      console.error(e);
      setMsg('❌ Error en registro: ' + e.message);
    }
  };

  const handleLogin = async () => {
    try {
      setMsg('📥 Pidiendo opciones de login...');
      const options = await postJSON(`${API_BASE}/login/options`, { username });
      const asseResp = await startAuthentication({ optionsJSON: options });
      const v = await postJSON(`${API_BASE}/login/verify`, { username, credential: asseResp });
      setMsg(v.verified ? '✅ Login OK' : '❌ Login no verificado');
    } catch (e) {
      console.error(e);
      setMsg('❌ Error en login: ' + e.message);
    }
  };

  return (
    <div style={{display:'flex',flexDirection:'column',gap:12,alignItems:'center',marginTop:40}}>
      <h1>🔐 Demo Passkeys (v13)</h1>
      <input
        placeholder="Usuario"
        value={username}
        onChange={e => setUsername(e.target.value)}
        style={{padding:8}}
      />
      <div style={{display:'flex',gap:8}}>
        <button onClick={handleRegister}>Registrar passkey</button>
        <button onClick={handleLogin}>Ingresar con passkey</button>
      </div>
      <div>{msg}</div>
    </div>
  );
}
