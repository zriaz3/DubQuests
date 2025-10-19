// public/js/auth-guard.js
import { api, auth } from './app-api.js';

const SIGN_IN_PAGE = '/index.html';   

export async function requireLogin() {
  if (!auth.token()) {
    window.location.href = SIGN_IN_PAGE;
    return null;
  }
  // session restore cache
  const cached = sessionStorage.getItem('me');
  if (cached) return JSON.parse(cached);

  try {
    const me = await api.me();
    sessionStorage.setItem('me', JSON.stringify(me));
    return me;
  } catch (err) {
    // token likely invalid/expired
    auth.clear();
    sessionStorage.removeItem('me');
    window.location.href = SIGN_IN_PAGE;
    return null;
  }
}

export function logout() {
  auth.clear();
  sessionStorage.removeItem('me');
  window.location.href = SIGN_IN_PAGE;
}
