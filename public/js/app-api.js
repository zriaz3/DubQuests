// public/js/app-api.js
export const API_BASE = window.location.hostname.includes('localhost')
  ? 'http://localhost:3000'
  : 'https://<your-render-service>.onrender.com';   // ← change to your Render URL

export const auth = {
  token: () => localStorage.getItem('token'),
  set:   (t) => localStorage.setItem('token', t),
  clear: () => localStorage.removeItem('token')
};

async function request(path, { method='GET', body=null, authRequired=false, headers={} } = {}) {
  const h = { 'Content-Type':'application/json', ...headers };
  if (authRequired) h.Authorization = `Bearer ${auth.token()||''}`;
  const res = await fetch(`${API_BASE}${path}`, { method, headers: h, body: body ? JSON.stringify(body) : null });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

export const api = {
  register: (name, username, email, password) =>
    request('/auth/register', { method: 'POST', body: { name, username, email, password } }),
  login: (identifier, password) =>
    request('/auth/login', { method: 'POST', body: { identifier, password } }),
  me: () => request('/me', { authRequired: true }),
  // ... (rest unchanged)
};
