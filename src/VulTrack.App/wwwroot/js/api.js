import { state, updateAuthUi } from './state.js';

export async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { 'content-type': 'application/json' },
    ...options
  });
  const body = await res.json();
  if (!res.ok || body.ok === false) {
    if (res.status === 401) {
      state.authenticated = false;
      state.username = null;
      updateAuthUi();
    }
    throw new Error(body.error?.message ?? `Request failed: ${res.status}`);
  }
  return body.data;
}

export async function loadAuthSession() {
  try {
    const data = await api('/api/v1/auth.session');
    state.authenticated = Boolean(data.authenticated);
    state.username = data.username;
  } catch {
    state.authenticated = false;
    state.username = null;
  }
  updateAuthUi();
}
