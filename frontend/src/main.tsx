import React, { useState } from 'react'
import { createRoot } from 'react-dom/client'

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000'

function App() {
  const [health, setHealth] = useState('unknown')
  const [ready, setReady] = useState('unknown')

  const checkHealth = async () => {
    try {
      const res = await fetch(`${API}/health`)
      const data = await res.json()
      setHealth(data.status)
    } catch {
      setHealth('down')
    }
  }

  const checkReady = async () => {
    try {
      const res = await fetch(`${API}/health/ready`)
      const data = await res.json()
      setReady(data.status)
    } catch {
      setReady('not-ready')
    }
  }

  return (
    <div style={{ fontFamily: 'Arial', padding: 24 }}>
      <h1>FortiWeb Assessment Platform — Phase 1</h1>
      <p>Frontend skeleton wired to backend and health endpoints.</p>
      <div style={{ display: 'flex', gap: 12 }}>
        <button onClick={checkHealth}>Check API health</button>
        <button onClick={checkReady}>Check API readiness</button>
      </div>
      <p>Health: <b>{health}</b></p>
      <p>Ready: <b>{ready}</b></p>
      <p>Next phases will add ingestion, parsing, scoring, and reporting UX flows.</p>
    </div>
  )
}

createRoot(document.getElementById('root')!).render(<App />)
