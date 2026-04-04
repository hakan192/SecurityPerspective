import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

function App() {
  const [dashboard, setDashboard] = useState({ snapshots: [], assessments: [], pending_jobs: 0 });
  const [error, setError] = useState('');
  const [username, setUsername] = useState(localStorage.getItem('sp_user') || 'viewer');
  const [password, setPassword] = useState('');
  const [authHeader, setAuthHeader] = useState('');

  const loadDashboard = () => {
    if (!authHeader) return;
    setError('');
    fetch('/api/dashboard', {
      headers: { Authorization: authHeader },
    })
      .then((r) => {
        if (!r.ok) throw new Error('Unable to load dashboard. Check credentials/role.');
        return r.json();
      })
      .then(setDashboard)
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    if (authHeader) {
      loadDashboard();
    }
  }, [authHeader]);

  const onLogin = (e) => {
    e.preventDefault();
    localStorage.setItem('sp_user', username);
    setAuthHeader('Basic ' + btoa(`${username}:${password}`));
    setPassword('');
  };

  return (
    <main style={{ fontFamily: 'Arial, sans-serif', margin: '2rem' }}>
      <h1>SecurityPerspective</h1>
      <p>React dashboard for configuration visibility and maturity scorecards.</p>

      <form onSubmit={onLogin} style={{ marginBottom: '1rem' }}>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="username" />{' '}
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="password" />{' '}
        <button type="submit">Authenticate</button>{' '}
        <button type="button" onClick={loadDashboard}>Refresh</button>
      </form>

      {error && <p style={{ color: 'crimson' }}>{error}</p>}
      <section>
        <h2>Queue</h2>
        <p>Pending background jobs: <strong>{dashboard.pending_jobs}</strong></p>
      </section>
      <section>
        <h2>Recent Snapshots</h2>
        <ul>
          {dashboard.snapshots.map((s) => (
            <li key={s.id}>#{s.id} - {s.source} - {new Date(s.collected_at).toLocaleString()}</li>
          ))}
        </ul>
      </section>
      <section>
        <h2>Scorecards</h2>
        <ul>
          {dashboard.assessments.map((a) => (
            <li key={`${a.snapshot_id}-${a.assessed_at}`}>
              Snapshot #{a.snapshot_id}: {a.overall_score}% ({a.maturity_level})
            </li>
          ))}
        </ul>
      </section>
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
