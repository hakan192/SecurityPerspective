const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export async function login(username: string, password: string) {
  const body = new URLSearchParams({ username, password })
  const res = await fetch(`${API}/api/v1/auth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body })
  if (!res.ok) throw new Error('login failed')
  return res.json()
}

export async function authed(path: string, token: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, { ...init, headers: { ...(init?.headers || {}), Authorization: `Bearer ${token}` } })
  if (!res.ok) throw new Error(`request failed: ${path}`)
  return res
}
